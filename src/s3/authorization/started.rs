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

/// The most signing bytes carried on one line of the copy's output, well
/// inside what the starting machine accepts as one line once encoded.
const LINE_BYTES: usize = 48 * 1024;

/// What the command typed on this machine lets the server's copy ask for:
/// its bucket, the keys under its S3 source or destination, and only the
/// operations it implies. The server supplies none of this. Its URLs last as
/// long as those signed for any `--auth-from` copy ([`DEFAULT_LIFETIME`]).
pub(crate) fn request(args: &crate::cli::Args) -> Result<Request> {
    let mut options = args
        .s3
        .clone()
        .context("a copy between a server and storage names s3://")?;
    anyhow::ensure!(
        !args.rm && !options.route.is_server_copy() && args.descriptor_copy.is_none(),
        "this machine signs storage requests only for a file or tree copy between a server and a bucket"
    );
    refuse_customer_keys(&options)?;
    // As for a copy run here, this machine's environment may name the endpoint.
    options.endpoint = options
        .endpoint
        .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
        .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
    request_for(args, &options)
}

/// Refuse headers that carry a customer-provided encryption key (SSE-C):
/// the server makes the storage requests, so the key would go to it.
fn refuse_customer_keys(options: &crate::s3::Options) -> Result<()> {
    let customer_key = options
        .headers
        .iter()
        .map(|header| ("--s3-header", header))
        .chain(
            options
                .write_headers
                .iter()
                .map(|header| ("--s3-write-header", header)),
        )
        .find(|(_, crate::s3::Header(name, _))| {
            name.to_ascii_lowercase()
                .contains("server-side-encryption-customer-")
        });
    if let Some((flag, crate::s3::Header(name, _))) = customer_key {
        anyhow::bail!(
            "{flag} {name} is not supported for a copy between an SSH server and S3 started on another machine: the server makes the storage requests, so the customer-provided encryption key would be sent to it. Run syq on the server to copy with that key"
        );
    }
    Ok(())
}

/// The receiving machine the command names with `--auth-from @NAME` to
/// approve the copy and sign for it, instead of this machine. It derives
/// the same request from the command.
pub(crate) fn receiving_machine(args: &crate::cli::Args) -> Option<&str> {
    match &args.auth_from {
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) => Some(name),
        _ => None,
    }
}

/// A signer for [`request`], using this machine's storage credentials.
pub(crate) fn signer(request: Request) -> Result<Signer> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Signer::new(request))
        .context("prepare to sign the server's storage requests with this machine's credentials")
}

/// A time as messages show it.
pub(crate) fn time(seconds: u64) -> String {
    aws_smithy_types::DateTime::from_secs(seconds as i64)
        .fmt(aws_smithy_types::date_time::Format::DateTime)
        .unwrap_or_else(|_| format!("{seconds} seconds after 1970"))
}

/// A lifetime as messages show it, in whole days or hours where it has them.
pub(crate) fn duration(seconds: u64) -> String {
    let unit =
        |count: u64, name: &str| format!("{count} {name}{}", if count == 1 { "" } else { "s" });
    match seconds {
        _ if seconds.is_multiple_of(86400) => unit(seconds / 86400, "day"),
        _ if seconds.is_multiple_of(3600) => unit(seconds / 3600, "hour"),
        _ => unit(seconds, "second"),
    }
}

/// What the starting machine says once when its credentials expire, and its
/// signed URLs with them, well before their requested lifetime is up.
pub(crate) fn early_expiry_notice(configuration: &Configuration) -> Option<String> {
    let full = now().ok()?.checked_add(configuration.requested_lifetime)?;
    (configuration.expires_at + 300 < full).then(|| {
        format!(
            "this machine's storage credentials expire at {}, and the URLs it signs for the server with them; a copy still running then fails its remaining files and can be run again to continue",
            time(configuration.expires_at)
        )
    })
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
) -> Result<(
    Authorization,
    Vec<crate::s3::Header>,
    Vec<crate::s3::Header>,
)> {
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
        crate::cli::Args::parse_args(&words.iter().map(OsString::from).collect::<Vec<_>>()).unwrap()
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
        "cp",
        "--from",
        "server",
        "--srcs-in",
        "/srv/dataset",
        "--to",
        "s3://bucket",
        "--into",
        "backups/dataset",
    ];
    fn with(base: &[&'static str], more: &[&'static str]) -> Vec<&'static str> {
        base.iter().chain(more).copied().collect()
    }

    #[test]
    fn an_upload_signs_writes_under_its_destination_only() {
        let request = request(&command(UPLOAD)).unwrap();
        assert_eq!(request.bucket, "bucket");
        assert_eq!(request.lifetime, DEFAULT_LIFETIME);
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
            Unsigned::new("GET", "")
                .query("versions", "")
                .query("prefix", "backups/dataset/"),
            Unsigned::new("PUT", "backups/dataset/a").query("acl", ""),
            Unsigned::new("PUT", "backups/dataset/a").header("x-amz-acl", "public-read"),
            // Copying an object the command does not name into the destination.
            Unsigned::new("PUT", "backups/dataset/a")
                .header("x-amz-copy-source", "/bucket/secrets"),
            // A header the command did not add.
            Unsigned::new("PUT", "backups/dataset/a")
                .header("x-amz-object-lock-mode", "COMPLIANCE"),
        ] {
            assert!(!permits(&request, refused.clone()), "{refused:?}");
        }
    }

    fn keys(request: &Request) -> Vec<&str> {
        request
            .scopes
            .iter()
            .map(|scope| scope.key.as_str())
            .collect()
    }

    #[test]
    fn named_sources_sign_only_the_paths_their_names_produce() {
        let request = request(&command(&[
            "cp",
            "--from",
            "server",
            "/srv/project",
            "/srv/notes.txt",
            "--to",
            "s3://bucket",
            "--into",
            "backups",
        ]))
        .unwrap();
        assert_eq!(keys(&request), ["backups/notes.txt", "backups/project"]);
        for allowed in [
            // The named file, and the named directory with its marker,
            // contents and listing.
            Unsigned::new("HEAD", "backups/notes.txt"),
            Unsigned::new("PUT", "backups/notes.txt"),
            // This machine cannot see whether a name is a file or a
            // directory on the server, so each covers what lies below it.
            Unsigned::new("GET", "backups/notes.txt/child"),
            Unsigned::new("HEAD", "backups/project"),
            Unsigned::new("PUT", "backups/project/"),
            Unsigned::new("PUT", "backups/project/sub/a"),
            Unsigned::new("POST", "backups/project/big").query("uploads", ""),
            Unsigned::new("DELETE", "backups/project/big").query("uploadId", "1"),
            list("backups/project/"),
            list("backups/project/sub/"),
        ] {
            assert!(permits(&request, allowed.clone()), "{allowed:?}");
        }
        for refused in [
            // Siblings in the same --into directory.
            Unsigned::new("GET", "backups/other"),
            Unsigned::new("PUT", "backups/other/a"),
            Unsigned::new("PUT", "backups/project-private/a"),
            Unsigned::new("PUT", "backups/notes.txt.bak"),
            // The directory itself, and listing it.
            Unsigned::new("HEAD", "backups"),
            Unsigned::new("PUT", "backups/"),
            list("backups/"),
            list("backups/notes.txt"),
            list(""),
        ] {
            assert!(!permits(&request, refused.clone()), "{refused:?}");
        }
        // No placement option puts a named source at the top of the bucket,
        // which is all it then covers.
        let top = super::request(&command(&[
            "cp",
            "--from",
            "server",
            "project",
            "--to",
            "s3://bucket",
        ]))
        .unwrap();
        assert_eq!(keys(&top), ["project"]);
        assert!(permits(&top, Unsigned::new("PUT", "project/a")));
        assert!(!permits(&top, Unsigned::new("PUT", "other")));
        assert!(!permits(&top, list("")));
        // --as names the one key.
        let renamed = super::request(&command(&[
            "cp",
            "--from",
            "server",
            "project",
            "--to",
            "s3://bucket",
            "--as",
            "backups/copy",
        ]))
        .unwrap();
        assert_eq!(keys(&renamed), ["backups/copy"]);
    }

    #[test]
    fn the_whole_destination_is_signed_where_the_command_does_not_fix_the_names() {
        // The server's directory decides the names --srcs-in produces.
        assert_eq!(
            keys(&request(&command(UPLOAD)).unwrap()),
            ["backups/dataset"]
        );
        // A placement that tests the directory itself looks at all of it.
        let existing = request(&command(&[
            "cp",
            "--from",
            "server",
            "project",
            "--to",
            "s3://bucket",
            "--into-existing",
            "backups",
        ]))
        .unwrap();
        assert_eq!(keys(&existing), ["backups"]);
        assert!(permits(&existing, Unsigned::new("HEAD", "backups")));
        assert!(permits(&existing, list("backups/")));
        // More sources than a request lists one by one, as a receiving
        // machine's prompt shows for an upload typed where the files are.
        // A copy between a server and a bucket refuses them first.
        let names: Vec<String> = (0..1025).map(|index| format!("file-{index}")).collect();
        let mut words = vec!["cp", "--from", "server"];
        words.extend(names.iter().map(String::as_str));
        words.extend(["--to", "s3://bucket", "--into", "backups"]);
        assert_eq!(keys(&request(&command(&words)).unwrap()), ["backups"]);
    }

    #[test]
    fn customer_encryption_keys_are_not_sent_to_the_server() {
        for name in [
            "x-amz-server-side-encryption-customer-key",
            "X-Amz-Server-Side-Encryption-Customer-Algorithm",
            "x-amz-server-side-encryption-customer-key-MD5",
        ] {
            for flag in ["--s3-header", "--s3-write-header"] {
                let header = format!("{name}: value");
                for auth in [&[][..], &["--auth-from", "@laptop"][..]] {
                    let mut words: Vec<&str> = UPLOAD.to_vec();
                    words.extend([flag, header.as_str()]);
                    words.extend(auth);
                    let error = request(&command(&words)).unwrap_err().to_string();
                    assert!(
                        error.contains(&format!("{flag} {}", name.to_ascii_lowercase()))
                            && error.contains("customer-provided encryption key")
                            && error.contains("Run syq on the server"),
                        "{error}"
                    );
                }
            }
        }
        // A download sends the key to the server as well.
        let download = command(&[
            "cp",
            "--from",
            "s3://bucket",
            "--srcs-in",
            "dataset",
            "--to",
            "server",
            "--into",
            "dataset",
            "--s3-header",
            "x-amz-server-side-encryption-customer-key: value",
        ]);
        let error = request(&download).unwrap_err().to_string();
        assert!(error.contains("customer-provided"), "{error}");
        // Other headers, including server-side encryption with a key the
        // storage service holds, still travel.
        let other = request(&command(&with(
            UPLOAD,
            &[
                "--s3-header",
                "x-amz-server-side-encryption: aws:kms",
                "--s3-write-header",
                "x-amz-storage-class: STANDARD_IA",
            ],
        )))
        .unwrap();
        assert_eq!(other.headers.len(), 2);
    }

    #[test]
    fn signed_urls_last_as_long_as_for_any_auth_from_copy() {
        assert_eq!(DEFAULT_LIFETIME, 7 * 24 * 60 * 60);
        assert_eq!(
            request(&command(UPLOAD)).unwrap().lifetime,
            DEFAULT_LIFETIME
        );
        assert_eq!(duration(DEFAULT_LIFETIME), "7 days");
        assert_eq!(duration(3600), "1 hour");
        assert_eq!(duration(90), "90 seconds");
    }

    #[test]
    fn deletions_beyond_max_delete_are_not_signed() {
        let limited = request(&command(&with(UPLOAD, &["--prune", "--max-delete=2"]))).unwrap();
        assert_eq!(limited.max_delete, Some(2));
        let signer = Signer::fixture(limited);
        let delete = |key: &str| signer.sign(&Unsigned::new("DELETE", key));
        // Abandoning a multipart upload deletes no object.
        for _ in 0..5 {
            signer
                .sign(&Unsigned::new("DELETE", "backups/dataset/big").query("uploadId", "1"))
                .unwrap();
        }
        delete("backups/dataset/a").unwrap();
        delete("backups/dataset/b").unwrap();
        let error = delete("backups/dataset/c").unwrap_err().to_string();
        assert!(error.contains("no more than 2 object deletions"), "{error}");
        // Other requests are still signed.
        signer
            .sign(&Unsigned::new("PUT", "backups/dataset/c"))
            .unwrap();
        let none = Signer::fixture(
            request(&command(&with(UPLOAD, &["--prune", "--max-delete=0"]))).unwrap(),
        );
        assert!(none
            .sign(&Unsigned::new("DELETE", "backups/dataset/a"))
            .is_err());
        // Without the option there is nothing to count.
        let unlimited = request(&command(&with(UPLOAD, &["--prune"]))).unwrap();
        assert_eq!(unlimited.max_delete, None);
    }

    #[test]
    fn a_receiving_machine_named_by_the_command_signs_the_same_request() {
        let named = command(&with(UPLOAD, &["--auth-from", "@laptop"]));
        assert_eq!(receiving_machine(&named), Some("laptop"));
        let request = request(&named).unwrap();
        // What the receiving machine derives from the same command, which
        // is also what this machine would sign.
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::to_value(super::request(&command(UPLOAD)).unwrap()).unwrap()
        );
        assert_eq!(request.lifetime, DEFAULT_LIFETIME);
        crate::approval_command::check_storage(
            &named_words(&with(UPLOAD, &["--auth-from", "@laptop"])),
            &request,
            "laptop",
        )
        .unwrap();
        assert_eq!(receiving_machine(&command(UPLOAD)), None);
    }
    fn named_words(words: &[&str]) -> Vec<Vec<u8>> {
        words.iter().map(|word| word.as_bytes().to_vec()).collect()
    }

    #[test]
    fn a_dry_run_signs_no_change() {
        let request = request(&command(&with(UPLOAD, &["--dry-run", "--prune"]))).unwrap();
        assert!(!request.upload && !request.delete);
        assert!(permits(
            &request,
            Unsigned::new("HEAD", "backups/dataset/a")
        ));
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
        assert!(permits(
            &pruning,
            Unsigned::new("DELETE", "backups/dataset/a")
        ));
        assert!(!permits(&pruning, Unsigned::new("DELETE", "backups/other")));
        // Older versions stay: the command names none.
        assert!(!permits(
            &pruning,
            Unsigned::new("DELETE", "backups/dataset/a").query("versionId", "1")
        ));
        let keeping = request(&command(&with(UPLOAD, &["--if-exists=keep"]))).unwrap();
        assert!(keeping.create_only);
        assert!(!permits(
            &keeping,
            Unsigned::new("PUT", "backups/dataset/a")
        ));
        assert!(permits(
            &keeping,
            Unsigned::new("PUT", "backups/dataset/a").header("if-none-match", "*")
        ));
    }

    #[test]
    fn a_download_signs_reads_of_its_sources_only() {
        let request = request(&command(&[
            "cp",
            "--from",
            "s3://bucket",
            "--cwd",
            "backups",
            "dataset",
            "notes.txt",
            "--to",
            "server",
            "--into",
            "/srv/restore",
        ]))
        .unwrap();
        assert!(!request.upload && !request.delete);
        assert_eq!(
            request
                .scopes
                .iter()
                .map(|scope| scope.key.as_str())
                .collect::<Vec<_>>(),
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
            "cp",
            "--from",
            "s3://bucket",
            "--srcs-in",
            "backups",
            "--to",
            "server",
            "--into",
            "/srv/restore",
            "--prune",
        ]))
        .unwrap();
        assert!(!pruning.delete && !pruning.upload);
        assert!(!permits(&pruning, Unsigned::new("DELETE", "backups/a")));
    }

    #[test]
    fn only_a_copy_between_a_server_and_a_bucket_is_signed_for() {
        for words in [
            &["rm", "--on", "s3://bucket", "key"][..],
            &[
                "cp", "--from", "s3://a", "x", "--to", "s3://b", "--into", "y",
            ],
            &[
                "cp", "--from", "server", "x", "--to", "other", "--into", "y",
            ],
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
        assert!(
            error.contains("needs the same syq build on both machines"),
            "{error}"
        );
        // Standard input was not taken, and nothing was attached.
        assert!(args.storage_authorization.is_none());
        // A copy nobody else started is left alone.
        args.storage_signing = None;
        attach(&mut args).unwrap();
        assert!(args.storage_authorization.is_none());
    }

    #[test]
    fn credentials_that_expire_early_are_announced_and_named_at_expiry() {
        let mut signer = Signer::fixture(request(&command(UPLOAD)).unwrap());
        signer.configuration.requested_lifetime = DEFAULT_LIFETIME;
        signer.configuration.expires_at = now().unwrap() + DEFAULT_LIFETIME;
        assert_eq!(early_expiry_notice(&signer.configuration), None);
        signer.configuration.expires_at = now().unwrap() + 3600;
        let notice = early_expiry_notice(&signer.configuration).unwrap();
        assert!(
            notice.contains(&format!(
                "credentials expire at {}",
                time(signer.configuration.expires_at)
            )),
            "{notice}"
        );
        let (local, _remote) = UnixStream::pair().unwrap();
        let mut authorization = Authorization::new("bucket".into(), signer.configuration, local);
        authorization.started_elsewhere = true;
        authorization.configuration.expires_at = 1;
        let error = authorization
            .signed(Unsigned::new("GET", "backups/dataset/a"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("expired at 1970-01-01T00:00:01Z") && error.contains("credentials"),
            "{error}"
        );
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
        assert!(
            error.contains("check the date and time on both machines"),
            "{error}"
        );
    }
}
