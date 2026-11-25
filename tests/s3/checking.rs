//! A prefix whose objects nearly all match the destination already, behind
//! responses slow enough to see how many requests are in flight. It serves
//! the prefix as a source to download and as a destination to upload into.
use super::*;

/// Objects whose destination file matches. Their average size starts
/// transfers at 32 objects, and at 100 ms a request there are enough of
/// them to outlast the first samples at that rate several times over,
/// without the load that thousands of quick requests would put on the
/// tests running beside this one.
pub(super) const UNCHANGED: usize = 800;
pub(super) const SIZE: u64 = 2 * 1024 * 1024;
/// Objects with no destination file, listed after the unchanged ones.
pub(super) const CHANGED: usize = 48;
pub(super) const MODIFIED: u64 = 1_600_000_000;

pub(super) struct InFlight {
    now: AtomicUsize,
    peak: AtomicUsize,
}
impl InFlight {
    const fn new() -> Self {
        Self {
            now: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }
    fn enter(&self) {
        let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
    }
    fn leave(&self) {
        self.now.fetch_sub(1, Ordering::SeqCst);
    }
    /// Hold a request of this kind, which also counts among `REQUESTS`.
    fn hold(&self, time: Duration) {
        REQUESTS.enter();
        self.enter();
        thread::sleep(time);
        self.leave();
        REQUESTS.leave();
    }
    pub(super) fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
    pub(super) fn reset(&self) {
        self.peak
            .store(self.now.load(Ordering::SeqCst), Ordering::SeqCst);
    }
}
pub(super) static HEADS: InFlight = InFlight::new();
pub(super) static GETS: InFlight = InFlight::new();
pub(super) static PUTS: InFlight = InFlight::new();
/// Checks and transfers together.
pub(super) static REQUESTS: InFlight = InFlight::new();

/// Hold while counting this fixture's requests: the counters are shared by
/// every test in the process, as tests run under plain `cargo test`.
pub(super) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    static COUNTING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    COUNTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn key(index: usize) -> String {
    format!("data/f{index:05}")
}

pub(super) fn serve(
    socket: &mut TcpStream,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
) {
    let url = url::Url::parse(&format!("http://fixture{target}")).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
    let index = url
        .path()
        .strip_prefix("/bucket/data/f")
        .and_then(|index| index.parse::<usize>().ok());
    let object = |size: u64| {
        vec![
            ("Content-Length".into(), size.to_string()),
            ("ETag".into(), "\"stored\"".into()),
            (
                "Last-Modified".into(),
                "Sun, 13 Sep 2020 12:26:40 GMT".into(),
            ),
            ("x-amz-meta-syq-format".into(), "1".into()),
            ("x-amz-meta-syq-kind".into(), "file".into()),
            ("x-amz-meta-syq-mode".into(), "420".into()),
            (
                "x-amz-meta-syq-uid".into(),
                unsafe { libc::geteuid() }.to_string(),
            ),
            (
                "x-amz-meta-syq-gid".into(),
                unsafe { libc::getegid() }.to_string(),
            ),
            ("x-amz-meta-syq-mtime".into(), MODIFIED.to_string()),
            ("x-amz-meta-syq-mtime-nsec".into(), "0".into()),
        ]
    };
    match (method, index) {
        ("GET", _) if query.contains_key("list-type") => {
            // Honor every listing parameter: planning may split the listing.
            let prefix = query.get("prefix").map_or("", |prefix| prefix.as_ref());
            let after = query
                .get("continuation-token")
                .or_else(|| query.get("start-after"))
                .map_or("", |after| after.as_ref());
            let limit = query
                .get("max-keys")
                .map_or(1000, |limit| limit.parse().unwrap());
            let mut body = String::new();
            let mut prefixes = std::collections::BTreeSet::new();
            let mut listed = 0;
            let mut last = String::new();
            let mut truncated = false;
            for index in 0..UNCHANGED + CHANGED {
                let key = key(index);
                if !key.starts_with(prefix) || key.as_str() <= after {
                    continue;
                }
                let rest = &key[prefix.len()..];
                let common = query
                    .contains_key("delimiter")
                    .then(|| rest.find('/'))
                    .flatten()
                    .map(|slash| key[..prefix.len() + slash + 1].to_owned());
                if common
                    .as_ref()
                    .is_some_and(|common| prefixes.contains(common))
                {
                    continue;
                }
                if listed == limit {
                    truncated = true;
                    break;
                }
                listed += 1;
                match common {
                    Some(common) => {
                        // Everything under a common prefix sorts before this.
                        last = format!("{common}\u{10ffff}");
                        prefixes.insert(common);
                    }
                    None => {
                        let size = if index < UNCHANGED { SIZE } else { 1 };
                        body.push_str(&format!(
                            "<Contents><Key>{key}</Key><Size>{size}</Size></Contents>"
                        ));
                        last = key;
                    }
                }
            }
            for common in prefixes {
                body.push_str(&format!(
                    "<CommonPrefixes><Prefix>{common}</Prefix></CommonPrefixes>"
                ));
            }
            if truncated {
                body.push_str(&format!(
                    "<NextContinuationToken>{last}</NextContinuationToken>"
                ));
            }
            let body = format!(
                "<ListBucketResult><IsTruncated>{truncated}</IsTruncated>{body}</ListBucketResult>"
            );
            reply(socket, 200, &[], body.as_bytes(), false);
        }
        ("HEAD", Some(index)) if index < UNCHANGED => {
            HEADS.hold(Duration::from_millis(100));
            reply(socket, 200, &object(SIZE), b"", true);
        }
        ("HEAD", _) => reply(socket, 404, &[], b"", true),
        ("GET", Some(index)) if (UNCHANGED..UNCHANGED + CHANGED).contains(&index) => {
            GETS.hold(Duration::from_millis(50));
            reply(socket, 200, &object(1), b"x", false);
        }
        ("PUT", Some(index)) if (UNCHANGED..UNCHANGED + CHANGED).contains(&index) => {
            let mut body = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(body, b"x");
            PUTS.hold(Duration::from_millis(50));
            reply(
                socket,
                200,
                &[("ETag".into(), "\"put\"".into())],
                b"",
                false,
            );
        }
        _ => panic!("unexpected request {method} {target}"),
    }
}
