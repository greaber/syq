//! Approved account connections that say whether anything uses them.
//!
//! An approved account connection's keeper holds its authorization stream
//! open for as long as its SSH master lives, so the laptop or provider
//! that approved it never looks idle. Once the master has logged in, the
//! keeper sends `LINK` on that stream. From then on the stream carries no
//! agent requests: the approving side asks (`LinkRequest`) and the keeper
//! answers (`LinkReply`), so a switch to another syq build can end the
//! connections nothing uses, and wait for the ones in use. Both ends are
//! the same build: every account request checks that before relaying.
use super::*;

/// Never an agent request: those begin with a message number of 1 or more.
pub(crate) const LINK: &[u8] = b"\0syq-account-link-v1";
/// A connection's report counts this long.
const FRESH: Duration = Duration::from_secs(15);
/// Ask again once a report is this old and someone wants to know.
const REFRESH: Duration = Duration::from_secs(5);
/// How long a switch waits for idle connections to end. It answers a
/// request that waits at most a second (`receive_service::send`); a keeper
/// answers within its 100 ms poll and the network's round trip.
pub(crate) const CLOSE_WAIT: Duration = Duration::from_millis(600);
/// Longest wait between looks at whether the stream should end.
const LOOK: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum LinkRequest {
    /// Whether anything uses the connection now.
    Query,
    /// End the connection if nothing uses it.
    CloseIfIdle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum LinkReply {
    Idle,
    /// Something uses it.
    InUse,
    /// The keeper cannot tell whether anything uses it, as where it cannot
    /// count the sessions of its master.
    Unknown,
    /// Nothing used it: it ends now.
    Closing,
}

pub(crate) fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(message)?)
}

pub(crate) fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T> {
    serde_json::from_slice(frame).context("invalid account connection message")
}

#[derive(Default)]
struct LinkState {
    /// The last answer and when it came.
    report: Option<(Instant, LinkReply)>,
    /// A `Query` is wanted.
    query: bool,
    /// A `Query` awaits its answer.
    asking: bool,
    /// A `CloseIfIdle` is wanted, for this close attempt.
    close: Option<u64>,
    /// The answer to a `CloseIfIdle`: its attempt, and whether it closed.
    closed: Option<(u64, bool)>,
    /// The link is gone: it closed, or its stream ended.
    ended: bool,
}

struct Link {
    state: Mutex<LinkState>,
    answered: std::sync::Condvar,
    /// Writing wakes the thread that serves the link.
    wake: UnixStream,
}
impl Link {
    fn wake(&self) {
        let _ = (&self.wake).write(&[1]);
    }
}

/// The open account connections a service approved that say whether they
/// are used (`LINK`).
#[derive(Default)]
pub(crate) struct AccountLinks {
    links: Mutex<Vec<std::sync::Arc<Link>>>,
    /// Numbers close attempts, so that one never takes another's answer.
    attempts: AtomicU64,
}

/// What the links said recently (`AccountLinks::counts`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinkCounts {
    /// Links open now.
    pub(crate) open: usize,
    /// Of those, the ones that said nothing uses them.
    pub(crate) idle: usize,
    /// Of those, the ones that said something does. The rest have not
    /// said lately, or cannot tell.
    pub(crate) in_use: usize,
}

/// A close attempt (`AccountLinks::ask_close`).
pub(crate) struct Closing {
    attempt: u64,
    links: Vec<std::sync::Arc<Link>>,
}
impl Closing {
    /// Wait until `deadline` for the answers; whether all ended. Those in
    /// use stay.
    pub(crate) fn wait(self, deadline: Instant) -> bool {
        let attempt = self.attempt;
        let mut all = true;
        for link in &self.links {
            let mut state = link.state.lock().unwrap();
            let answered = |state: &LinkState| {
                state.ended || state.closed.is_some_and(|(of, _)| of == attempt)
            };
            while !answered(&state) {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                state = link.answered.wait_timeout(state, left).unwrap().0;
            }
            if !(state.ended || state.closed == Some((attempt, true))) {
                // Not asked yet, or in use: it stays open.
                if state.close == Some(attempt) {
                    state.close = None;
                }
                all = false;
            }
        }
        all
    }
}

impl AccountLinks {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.links.lock().unwrap().len()
    }

    /// How many of them said recently that nothing uses them.
    pub(crate) fn idle(&self) -> usize {
        self.counts().idle
    }

    /// What the links said recently. Asks again those whose answer is
    /// getting old, so that calling this now and then, as a service
    /// waiting to switch does, keeps the counts current.
    pub(crate) fn counts(&self) -> LinkCounts {
        let now = Instant::now();
        let links = self.links.lock().unwrap();
        let mut counts = LinkCounts {
            open: links.len(),
            ..LinkCounts::default()
        };
        for link in links.iter() {
            let mut state = link.state.lock().unwrap();
            let age = state.report.map(|(at, _)| now.duration_since(at));
            if age < Some(FRESH) {
                match state.report {
                    Some((_, LinkReply::Idle)) => counts.idle += 1,
                    Some((_, LinkReply::InUse)) => counts.in_use += 1,
                    _ => {}
                }
            }
            if age.is_none_or(|age| age >= REFRESH) && !state.query && !state.asking {
                state.query = true;
                drop(state);
                link.wake();
            }
        }
        counts
    }

    /// Ask every connection to end if nothing uses it, and wait until
    /// `deadline` for their answers; whether all ended. Those in use stay.
    pub(crate) fn close_idle(&self, deadline: Instant) -> bool {
        self.ask_close().wait(deadline)
    }

    /// Ask every connection to end if nothing uses it; `Closing::wait`
    /// waits for their answers.
    pub(crate) fn ask_close(&self) -> Closing {
        let attempt = self.attempts.fetch_add(1, Ordering::AcqRel) + 1;
        let links: Vec<_> = self.links.lock().unwrap().clone();
        for link in &links {
            link.state.lock().unwrap().close = Some(attempt);
            link.wake();
        }
        Closing { attempt, links }
    }

    /// Answer the keeper's `LINK`, then serve its connection until it ends,
    /// the requester disconnects or `cancelled`.
    pub(crate) fn serve(
        &self,
        stream: &mut (impl Read + Write + AsRawFd),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        crate::agent_broker::write_frame(stream, LINK)?;
        let (woken, wake) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        woken.set_nonblocking(true)?;
        wake.set_nonblocking(true)?;
        let link = std::sync::Arc::new(Link {
            state: Mutex::default(),
            answered: std::sync::Condvar::new(),
            wake,
        });
        self.links.lock().unwrap().push(link.clone());
        struct Registered<'a>(&'a AccountLinks, std::sync::Arc<Link>);
        impl Drop for Registered<'_> {
            fn drop(&mut self) {
                self.0
                    .links
                    .lock()
                    .unwrap()
                    .retain(|link| !std::sync::Arc::ptr_eq(link, &self.1));
                // A close waiting for this link learns it is gone.
                self.1.state.lock().unwrap().ended = true;
                self.1.answered.notify_all();
            }
        }
        let _registered = Registered(self, link.clone());
        let mut asked = None;
        loop {
            if asked.is_none() {
                let request = {
                    let mut state = link.state.lock().unwrap();
                    if let Some(attempt) = state.close.take() {
                        Some((LinkRequest::CloseIfIdle, attempt))
                    } else if std::mem::take(&mut state.query) {
                        state.asking = true;
                        Some((LinkRequest::Query, 0))
                    } else {
                        None
                    }
                };
                if let Some((request, attempt)) = request {
                    crate::agent_broker::write_frame(stream, &encode(&request)?)?;
                    asked = Some((request, attempt));
                }
            }
            let mut descriptors = [
                libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: woken.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as _,
                    LOOK.as_millis() as libc::c_int,
                )
            };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            while matches!((&woken).read(&mut [0; 64]), Ok(n) if n > 0) {}
            if descriptors[0].revents == 0 {
                // Nothing arrived, so a look at the stream sees only its
                // end. While an answer is due, the stream ending wakes poll.
                if asked.is_none() && cancelled() {
                    return Ok(());
                }
                continue;
            }
            let Some(frame) = crate::agent_broker::read_frame(stream)? else {
                return Ok(());
            };
            let Some((request, attempt)) = asked.take() else {
                bail!("unexpected message on an approved account connection");
            };
            let reply: LinkReply = decode(&frame)?;
            let mut state = link.state.lock().unwrap();
            state.report = Some((Instant::now(), reply));
            if request == LinkRequest::Query {
                state.asking = false;
            }
            if request == LinkRequest::CloseIfIdle {
                state.closed = Some((attempt, reply == LinkReply::Closing));
            }
            drop(state);
            link.answered.notify_all();
            if reply == LinkReply::Closing {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keeper stand-in that answers each request with the next reply,
    /// then takes one more request, or the stream's end, and hangs up.
    fn keeper(mut stream: UnixStream, replies: Vec<LinkReply>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            crate::agent_broker::write_frame(&mut stream, LINK).unwrap();
            assert_eq!(
                crate::agent_broker::read_frame(&mut stream)
                    .unwrap()
                    .unwrap(),
                LINK
            );
            for reply in replies {
                let Some(frame) = crate::agent_broker::read_frame(&mut stream).unwrap() else {
                    return;
                };
                let request: LinkRequest = decode(&frame).unwrap();
                if reply == LinkReply::Closing {
                    assert_eq!(request, LinkRequest::CloseIfIdle);
                }
                crate::agent_broker::write_frame(&mut stream, &encode(&reply).unwrap()).unwrap();
            }
            let _ = crate::agent_broker::read_frame(&mut stream);
        })
    }

    fn serving(
        links: &std::sync::Arc<AccountLinks>,
        replies: Vec<LinkReply>,
    ) -> (
        std::thread::JoinHandle<()>,
        std::thread::JoinHandle<Result<()>>,
        UnixStream,
    ) {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let end = ours.try_clone().unwrap();
        let keeper = keeper(theirs, replies);
        assert_eq!(
            crate::agent_broker::read_frame(&mut ours).unwrap().unwrap(),
            LINK
        );
        let links = links.clone();
        let server = std::thread::spawn(move || links.serve(&mut ours, &|| false));
        (keeper, server, end)
    }

    fn wait_for(what: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A connection counts as idle only once it said so, and asking for
    /// the count asks it; one that ends when asked leaves the service.
    #[test]
    fn an_idle_connection_is_counted_once_it_says_so_and_ends_when_asked() {
        let links = std::sync::Arc::new(AccountLinks::default());
        let (keeper, server, end) = serving(&links, vec![LinkReply::Idle, LinkReply::Closing]);
        wait_for(|| links.links.lock().unwrap().len() == 1);
        // Not yet asked: it counts as in use, and the call asks it.
        assert_eq!(links.idle(), 0);
        wait_for(|| links.idle() == 1);
        assert!(links.close_idle(Instant::now() + Duration::from_secs(10)));
        server.join().unwrap().unwrap();
        drop(end);
        keeper.join().unwrap();
        assert!(links.links.lock().unwrap().is_empty());
        assert_eq!(links.idle(), 0);
    }

    /// Only a recent answer that something uses it counts a connection as
    /// in use: not one that has not answered yet, one that cannot tell,
    /// nor an answer grown old.
    #[test]
    fn only_a_recent_answer_counts_a_connection_in_use() {
        let links = std::sync::Arc::new(AccountLinks::default());
        let (keeper, server, end) = serving(&links, vec![LinkReply::Unknown, LinkReply::InUse]);
        wait_for(|| links.len() == 1);
        let link = links.links.lock().unwrap()[0].clone();
        // Not answered yet; the look asks it.
        assert_eq!(
            links.counts(),
            LinkCounts {
                open: 1,
                idle: 0,
                in_use: 0
            }
        );
        wait_for(|| link.state.lock().unwrap().report.is_some());
        assert_eq!(
            link.state.lock().unwrap().report.unwrap().1,
            LinkReply::Unknown
        );
        assert_eq!(links.counts().in_use, 0);
        // An old answer is asked again, and counts once answered.
        link.state.lock().unwrap().report = Some((Instant::now() - FRESH, LinkReply::Unknown));
        links.counts();
        wait_for(|| links.counts().in_use == 1);
        link.state.lock().unwrap().report = Some((Instant::now() - FRESH, LinkReply::InUse));
        // This look asks again. The keeper, out of answers, takes the
        // question and hangs up, which ends the stream. Shutting down our
        // end instead could race the server's write of that question.
        assert_eq!(links.counts().in_use, 0);
        keeper.join().unwrap();
        server.join().unwrap().unwrap();
        drop(end);
    }

    /// A connection that ends while a close waits counts as ended at once,
    /// rather than as one that did not answer in time.
    #[test]
    fn a_connection_that_ends_during_a_close_counts_as_ended() {
        let links = std::sync::Arc::new(AccountLinks::default());
        // Its keeper ends instead of answering.
        let (keeper, server, end) = serving(&links, Vec::new());
        wait_for(|| links.len() == 1);
        let closing = links.ask_close();
        keeper.join().unwrap();
        drop(end);
        let started = Instant::now();
        assert!(closing.wait(Instant::now() + Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_secs(5));
        server.join().unwrap().unwrap();
    }

    /// One in use stays open, and the close says not all ended.
    #[test]
    fn a_connection_in_use_stays_open() {
        let links = std::sync::Arc::new(AccountLinks::default());
        let (keeper, server, end) = serving(&links, vec![LinkReply::InUse, LinkReply::InUse]);
        wait_for(|| links.links.lock().unwrap().len() == 1);
        links.idle();
        wait_for(|| {
            links.links.lock().unwrap()[0]
                .state
                .lock()
                .unwrap()
                .report
                .is_some()
        });
        assert_eq!(links.idle(), 0);
        assert!(!links.close_idle(Instant::now() + Duration::from_secs(10)));
        assert_eq!(links.links.lock().unwrap().len(), 1);
        // The stream ends, as when the service stops.
        end.shutdown(std::net::Shutdown::Both).unwrap();
        keeper.join().unwrap();
        server.join().unwrap().unwrap();
    }
}
