//! Storage signing sessions end before data transfer. Closing receiving after
//! preparation cannot revoke already issued provider bearer capabilities.
use super::*;
use crate::s3::authorization::{Configuration, Request, Signer, Unsigned};

#[derive(Serialize, Deserialize)]
enum SigningRequest {
    Sign(Vec<Unsigned>),
    Finish,
}
#[derive(Serialize, Deserialize)]
enum SigningReply {
    Configuration(Configuration),
    Signed(Vec<String>),
    Finished,
    Error(String),
}

pub(crate) fn connect(name: &str, request: Request) -> Result<(UnixStream, Configuration)> {
    validate_name(name)?;
    request.validate()?;
    let registration = load_registration(name)?;
    // Unlike existing copies, this new operation cannot be handed to a released
    // helper that predates it. Reject before interpreting any new request bytes.
    if registration.identity != crate::identity::build() {
        bail!("storage authorization requires matching syq builds; reconnect from the authorizing machine with this build");
    }
    crate::output::diagnostic!("syq: requesting storage permission from @{name}; approve on that machine with its desktop prompt or syq persist receive pending");
    let (mut stream, reply) = exchange(
        &registration,
        Message::Storage(request),
        REQUEST_TIMEOUT + Duration::from_secs(10),
    )?;
    anyhow::ensure!(
        matches!(reply, Reply::Ready),
        "unexpected storage approval response"
    );
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    let configuration = match read_message(&mut stream)? {
        SigningReply::Configuration(configuration) => configuration,
        SigningReply::Error(error) => bail!("authorizing machine: {error}"),
        _ => bail!("invalid storage authorization configuration"),
    };
    Ok((stream, configuration))
}
pub(crate) fn sign(stream: &mut UnixStream, requests: &[Unsigned]) -> Result<Vec<String>> {
    let mut result = Vec::with_capacity(requests.len());
    // Both request descriptions and returned URLs are bounded by the existing
    // wire frame limit, including long keys and provider upload IDs.
    for range in batches(requests, |batch| {
        serde_json::to_vec(&SigningRequest::Sign(batch.to_vec()))
    })? {
        write_message(
            stream,
            &SigningRequest::Sign(requests[range.clone()].to_vec()),
        )?;
        let expected = result.len() + range.len();
        while result.len() < expected {
            match read_message(stream).context(
                "authorizing machine disconnected during preparation; reconnect and rerun the copy",
            )? {
                SigningReply::Signed(urls) => {
                    anyhow::ensure!(
                        !urls.is_empty() && result.len() + urls.len() <= expected,
                        "invalid storage signing response length"
                    );
                    result.extend(urls);
                }
                SigningReply::Error(error) => bail!("authorizing machine: {error}"),
                _ => bail!("invalid storage signing response"),
            }
        }
    }
    Ok(result)
}
fn batches<T>(
    values: &[T],
    encode: impl Fn(&[T]) -> serde_json::Result<Vec<u8>>,
) -> Result<Vec<std::ops::Range<usize>>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < values.len() {
        let mut end = (start + 128).min(values.len());
        while encode(&values[start..end])?.len() > MAX_MESSAGE {
            anyhow::ensure!(
                end - start > 1,
                "storage request exceeds the signing message limit"
            );
            end = start + (end - start) / 2;
        }
        ranges.push(start..end);
        start = end;
    }
    Ok(ranges)
}
pub(crate) fn finish(stream: &mut UnixStream) -> Result<()> {
    write_message(stream, &SigningRequest::Finish)?;
    anyhow::ensure!(
        matches!(read_message(stream)?, SigningReply::Finished),
        "storage authorization did not finish"
    );
    Ok(())
}

impl Receiver {
    pub(super) fn storage(&self, request: Request, mut stream: TrackedStream) -> Result<()> {
        request.validate()?;
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another request is awaiting approval; retry after it is decided")
        })?;
        let (generation, _channel) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        self.approvals
            .request_storage(&self.requester, &request, self.notifications, cancelled)?;
        drop(request_lock);
        anyhow::ensure!(
            !cancelled(),
            "storage authorization cancelled before preparation"
        );
        write_message(&mut stream, &Reply::Ready)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let signer = runtime.block_on(Signer::new(request))?;
        write_message(
            &mut stream,
            &SigningReply::Configuration(signer.configuration.clone()),
        )?;
        // A hashing/preparation phase can take longer than a network request.
        // The owned receiver registry closes this stream on cancellation.
        socket.set_read_timeout(None)?;
        loop {
            anyhow::ensure!(
                !cancelled(),
                "storage authorization cancelled during preparation"
            );
            match read_message(&mut stream)? {
                SigningRequest::Sign(requests) => match (|| -> Result<Vec<String>> {
                    anyhow::ensure!(requests.len() <= 128, "oversized storage signing batch");
                    requests
                        .iter()
                        .map(|request| signer.sign(request))
                        .collect()
                })() {
                    Ok(urls) => {
                        for range in batches(&urls, |batch| {
                            serde_json::to_vec(&SigningReply::Signed(batch.to_vec()))
                        })? {
                            write_message(
                                &mut stream,
                                &SigningReply::Signed(urls[range].to_vec()),
                            )?;
                        }
                    }
                    Err(error) => {
                        write_message(&mut stream, &SigningReply::Error(error.to_string()))?;
                        return Ok(());
                    }
                },
                SigningRequest::Finish => {
                    write_message(&mut stream, &SigningReply::Finished)?;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_batches_bound_both_descriptions_and_bearer_urls() {
        let urls = vec!["x".repeat(9000); 129];
        let ranges = batches(&urls, |values| {
            serde_json::to_vec(&SigningReply::Signed(values.to_vec()))
        })
        .unwrap();
        assert!(ranges.len() > 4);
        assert_eq!(
            ranges.iter().map(|range| range.len()).sum::<usize>(),
            urls.len()
        );
        let mut end = 0;
        for range in ranges {
            assert_eq!(range.start, end);
            end = range.end;
            assert!(
                serde_json::to_vec(&SigningReply::Signed(urls[range].to_vec()))
                    .unwrap()
                    .len()
                    <= MAX_MESSAGE
            );
        }
        assert!(
            batches(&["x".repeat(MAX_MESSAGE)], |values| serde_json::to_vec(
                values
            ))
            .is_err()
        );
    }
}
