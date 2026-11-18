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
    let (mut local, remote) = UnixStream::pair().context("create the storage signing channel")?;
    let outgoing = remote
        .try_clone()
        .context("create the storage signing channel")?;
    crate::remote_to_remote::follow_requester_signing(args, remote)?;
    std::thread::Builder::new()
        .name("storage-signing".into())
        .spawn(move || send_lines(outgoing, &line_prefix(&token)))
        .context("start the storage signing channel")?;
    let opening = crate::destination::storage::open_started_copy(&mut local)
        .context("the machine that started this copy ended before it could sign storage requests")?;
    anyhow::ensure!(
        now()? < opening.configuration.expires_at,
        "the storage URLs the machine that started this copy signs have already expired by this server's clock; check the date and time on both machines"
    );
    let options = args.s3.as_mut().expect("checked above");
    let header = |(name, value): (String, String)| {
        format!("{name}: {value}")
            .parse::<crate::s3::Header>()
            .map_err(|error| anyhow::anyhow!("invalid storage header from the machine that started this copy: {error}"))
    };
    options.headers = opening
        .headers
        .into_iter()
        .map(header)
        .collect::<Result<_>>()?;
    options.write_headers = opening
        .write_headers
        .into_iter()
        .map(header)
        .collect::<Result<_>>()?;
    let mut authorization = Authorization::new(bucket, opening.configuration, local);
    authorization.started_elsewhere = true;
    args.storage_authorization = Some(Arc::new(authorization));
    Ok(())
}

/// Write what the copy sends on its signing session as marked lines of
/// standard output, which the starting machine picks out of the copy's other
/// output.
fn send_lines(mut session: UnixStream, prefix: &str) {
    use base64::Engine as _;
    let mut buffer = vec![0u8; LINE_BYTES];
    loop {
        match session.read(&mut buffer) {
            Ok(0) => return,
            Ok(length) => {
                let line = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&buffer[..length]);
                if crate::output::write_stdout(format_args!("{prefix}{line}")).is_err() {
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
