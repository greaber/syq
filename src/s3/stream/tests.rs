use super::*;
use crate::{
    cli::Args,
    descriptor_copy::{controls::Controls, report::Report},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Seek, SeekFrom, Write},
    sync::{atomic::AtomicUsize, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Store {
    objects: BTreeMap<String, Vec<u8>>,
    parts: BTreeMap<(String, usize), Vec<u8>>,
    aborted: usize,
}
async fn serve(
    mut socket: tokio::net::TcpStream,
    store: Arc<Mutex<Store>>,
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(socket.read_u8().await.unwrap());
        assert!(headers.len() < 65536);
    }
    let headers = String::from_utf8(headers).unwrap();
    let mut lines = headers.lines();
    let request: Vec<_> = lines.next().unwrap().split_whitespace().collect();
    let method = request[0];
    let uri = url::Url::parse(&format!("http://fixture{}", request[1])).unwrap();
    let key = uri.path().to_owned();
    let fields: BTreeMap<_, _> = lines
        .filter_map(|s| s.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length = fields
        .get("content-length")
        .map_or(0, |v| v.parse::<usize>().unwrap());
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await.unwrap();
    let data = matches!(method, "PUT" | "GET");
    if data {
        let count = active.fetch_add(1, Relaxed) + 1;
        maximum.fetch_max(count, Relaxed);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (status, body, extra) = {
        let mut store = store.lock().unwrap();
        let query: BTreeMap<_, _> = uri.query_pairs().collect();
        match method {
            "POST" if query.contains_key("uploads") => (200, b"<InitiateMultipartUploadResult><UploadId>fixture</UploadId></InitiateMultipartUploadResult>".to_vec(), String::new()),
            "PUT" if key.ends_with("/bad") => (500, b"<Error><Code>InternalError</Code></Error>".to_vec(), String::new()),
            "PUT" => {
                if let Some(number) = query.get("partNumber") {
                    store.parts.insert((key.clone(), number.parse().unwrap()), body);
                } else { store.objects.insert(key.clone(), body); }
                (200, Vec::new(), "ETag: \"fixture\"\r\n".into())
            }
            "POST" => {
                let bytes: Vec<u8> = store.parts.iter().filter(|((k,_),_)| k == &key).flat_map(|(_,v)| v.clone()).collect();
                store.objects.insert(key.clone(), bytes);
                store.parts.retain(|(k,_),_| k != &key);
                (200, b"<CompleteMultipartUploadResult><ETag>\"fixture\"</ETag></CompleteMultipartUploadResult>".to_vec(), String::new())
            }
            "DELETE" => {
                store.parts.retain(|(k,_),_| k != &key);
                store.aborted += 1;
                (204, Vec::new(), String::new())
            }
            "HEAD" => {
                let size = store.objects[&key].len();
                (200, Vec::new(), format!("Content-Length: {size}\r\nETag: \"fixture\"\r\n"))
            }
            "GET" => {
                let bytes = &store.objects[&key];
                let (start,end) = fields["range"].strip_prefix("bytes=").unwrap().split_once('-').unwrap();
                let (start,end) = (start.parse::<usize>().unwrap(), end.parse::<usize>().unwrap());
                (206, bytes[start..=end].to_vec(), format!("Content-Range: bytes {start}-{end}/{}\r\nETag: \"fixture\"\r\n", bytes.len()))
            }
            other => panic!("unexpected {other} {uri}"),
        }
    };
    if data {
        active.fetch_sub(1, Relaxed);
    }
    let length = if method == "HEAD" {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", body.len())
    };
    socket
        .write_all(
            format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\n{extra}{length}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    socket.write_all(&body).await.unwrap();
}
fn arguments(upload: bool) -> Args {
    let argv = if upload {
        vec![
            "cp",
            "--quiet",
            "--src-fd",
            "0",
            "--to",
            "s3://fixture",
            "--as",
            "object",
        ]
    } else {
        vec![
            "cp",
            "--quiet",
            "object",
            "--from",
            "s3://fixture",
            "--as-fd",
            "1",
        ]
    };
    Args::parse_args(&argv.into_iter().map(Into::into).collect::<Vec<_>>()).unwrap()
}
fn input(bytes: &[u8]) -> File {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f
}
async fn copy(
    session: &Session,
    key: &str,
    file: File,
    upload: bool,
    commit: Option<File>,
) -> Result<()> {
    let args = arguments(upload);
    let controls = Controls::new(&args, Report::start(&args)?);
    let cancelled = Arc::new(AtomicBool::new(false));
    let descriptor = Descriptor::owned(file, upload, cancelled.clone())?;
    let commit = commit
        .map(|f| Descriptor::owned(f, true, cancelled.clone()))
        .transpose()?;
    let mut options = session.options.clone();
    options.route = if upload {
        super::super::Route::Upload
    } else {
        super::super::Route::Download
    };
    let plan = Plan {
        session,
        options,
        controls: &controls,
        key: key.into(),
        target: key.into(),
        placement: Default::default(),
        source_meta: None,
    };
    execute(
        &plan,
        upload.then_some(Source::Descriptor(0)),
        Some(descriptor),
        commit,
        cancelled,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entries_share_s3_admission_and_failed_producer_does_not_cancel_client() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let store = Arc::new(Mutex::new(Store::default()));
    let maximum = Arc::new(AtomicUsize::new(0));
    let server = {
        let (store, maximum) = (store.clone(), maximum.clone());
        tokio::spawn(async move {
            let active = Arc::new(AtomicUsize::new(0));
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept() => {
                        tasks.spawn(serve(socket.unwrap().0, store.clone(), active.clone(), maximum.clone()));
                    }
                    task = tasks.join_next(), if !tasks.is_empty() => { task.unwrap().unwrap(); }
                }
            }
        })
    };
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "fixture", "fixture", None, None, "fixture",
            ))
            .endpoint_url(&endpoint)
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .build(),
    );
    let mut options = arguments(true).s3.unwrap();
    options.endpoint = Some(endpoint);
    options.part_size = 8; // The independent fixture accepts tiny multipart parts.
    options.concurrency = 2;
    let session = Session {
        client,
        options,
        cancellation: Arc::default(),
        parts: Arc::new(tokio::sync::Semaphore::new(2)),
        requests: tokio::sync::Semaphore::new(2),
        objects: tokio::sync::Semaphore::new(3),
        bandwidth: None,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(
            copy(&session, "a", input(b"abcdefghijklmnopqrstuvw"), true, None),
            copy(
                &session,
                "b",
                input(b"123456789012345678901234567890"),
                true,
                None
            ),
            copy(&session, "c", input(b"short"), true, None),
        )
        .unwrap();
        let outputs = [tempfile::tempfile().unwrap(), tempfile::tempfile().unwrap()];
        tokio::try_join!(
            copy(&session, "a", outputs[0].try_clone().unwrap(), false, None),
            copy(&session, "b", outputs[1].try_clone().unwrap(), false, None),
        )
        .unwrap();
        use std::os::unix::fs::FileExt;
        let mut got = [0; 23];
        outputs[0].read_exact_at(&mut got, 0).unwrap();
        assert_eq!(&got, b"abcdefghijklmnopqrstuvw");
        let (failed, healthy) = tokio::join!(
            copy(
                &session,
                "a",
                input(b"uncommitted partial archive"),
                true,
                Some(input(b""))
            ),
            copy(
                &session,
                "next",
                input(b"another completed archive"),
                true,
                None
            ),
        );
        assert!(format!("{:#}", failed.unwrap_err()).contains("commit"));
        healthy.unwrap();
        assert!(copy(
            &session,
            "bad",
            input(b"failed transport archive"),
            true,
            None
        )
        .await
        .is_err());
        copy(&session, "last", input(b"still usable"), true, None)
            .await
            .unwrap();
    })
    .await
    .expect("S3 part admission must not deadlock");
    let state = store.lock().unwrap();
    assert_eq!(state.objects["/fixture/a"], b"abcdefghijklmnopqrstuvw");
    assert_eq!(state.objects["/fixture/last"], b"still usable");
    assert!(state.parts.is_empty());
    assert_eq!(state.aborted, 2);
    assert!(maximum.load(Relaxed) <= 2);
    assert_eq!(session.parts.available_permits(), 2);
    server.abort();
}
