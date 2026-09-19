use super::*;
use std::{fs::File, io::Write, os::fd::AsRawFd};

fn arguments(path: &std::path::Path, upload: bool) -> Args {
    let mut argv = vec![
        "cp".into(),
        "--quiet".into(),
        "--no-tcp".into(),
        "--performance-tuning".into(),
        "workers=2,request-size=4096".into(),
    ];
    if upload {
        argv.extend([
            "--src-fd".into(),
            "0".into(),
            "--as".into(),
            path.as_os_str().to_owned(),
        ]);
    } else {
        argv.extend([path.as_os_str().to_owned(), "--as-fd".into(), "1".into()]);
    }
    Args::parse_args(&argv).unwrap()
}
fn controls(args: &Args) -> Arc<Controls> {
    Arc::new(Controls::new(
        args,
        super::super::report::Report::start(args).unwrap(),
    ))
}
async fn copy(
    session: Arc<Session>,
    path: &std::path::Path,
    upload: bool,
    file: &File,
    commit: Option<&File>,
) -> Result<()> {
    let args = arguments(path, upload);
    let controls = controls(&args);
    let cancelled = Arc::new(AtomicBool::new(false));
    let descriptor = fd::Descriptor::open(file.as_raw_fd(), upload, cancelled.clone())?;
    let input_meta = upload.then(|| descriptor.metadata()).flatten();
    let commit = commit
        .map(|f| fd::Descriptor::open(f.as_raw_fd(), true, cancelled.clone()))
        .transpose()?;
    let (input, output) = if upload {
        (Some(descriptor), None)
    } else {
        (None, Some(descriptor))
    };
    execute(
        session,
        args.descriptor_copy.unwrap(),
        controls,
        cancelled,
        input,
        output,
        commit,
        input_meta,
    )
    .await
}
fn input(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entries_reuse_connections_release_tickets_and_abort_independently() {
    let dir = crate::test_support::tempdir().unwrap();
    let target = dir.path().join("target");
    let args = arguments(&target, true);
    let session = Session::connect(
        &args,
        args.descriptor_copy
            .as_ref()
            .unwrap()
            .location
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    // Exceed the broker's lifetime registration limit without widening it.
    for i in 0..260 {
        let bytes = (i as u64).to_le_bytes();
        copy(session.clone(), &target, true, &input(&bytes), None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }
    let output = tempfile::tempfile().unwrap();
    copy(session.clone(), &target, false, &output, None)
        .await
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut got = [0; 8];
    output.read_exact_at(&mut got, 0).unwrap();
    assert_eq!(got, 259u64.to_le_bytes());
    // EOF on the producer-success channel cannot publish a partial archive.
    let error = copy(
        session.clone(),
        &target,
        true,
        &input(b"partial"),
        Some(&input(b"")),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("commit"), "{error:#}");
    assert_eq!(std::fs::read(&target).unwrap(), got);
    copy(session.clone(), &target, true, &input(b"next"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"next");
    assert!(session.connections_created.load(Relaxed) <= 2);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_entries_share_workers_and_a_small_payload_budget() {
    let dir = crate::test_support::tempdir().unwrap();
    let targets = [
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("c"),
    ];
    let args = arguments(&targets[0], true);
    let mut session = Session::connect(
        &args,
        args.descriptor_copy
            .as_ref()
            .unwrap()
            .location
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    Arc::get_mut(&mut session).unwrap().budget = Arc::new(Semaphore::new(8192 / GRANULE));
    let inputs = [
        input(&vec![1; 256 * 1024]),
        input(&vec![2; 256 * 1024]),
        input(&vec![3; 256 * 1024]),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::try_join!(
            copy(session.clone(), &targets[0], true, &inputs[0], None),
            copy(session.clone(), &targets[1], true, &inputs[1], None),
            copy(session.clone(), &targets[2], true, &inputs[2], None),
        )
        .unwrap();
        let outputs = [
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
        ];
        tokio::try_join!(
            copy(session.clone(), &targets[0], false, &outputs[0], None),
            copy(session.clone(), &targets[1], false, &outputs[1], None),
            copy(session.clone(), &targets[2], false, &outputs[2], None),
        )
        .unwrap();
        use std::os::unix::fs::FileExt;
        for (i, file) in outputs.iter().enumerate() {
            let mut got = vec![0; 256 * 1024];
            file.read_exact_at(&mut got, 0).unwrap();
            assert_eq!(got, vec![i as u8 + 1; got.len()]);
        }
    })
    .await
    .expect("shared admission must not deadlock");
    assert!(session.connections_created.load(Relaxed) <= 2);
    assert_eq!(session.budget.available_permits(), 8192 / GRANULE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_quiet_owned_payload_retires_io_and_keeps_the_session_usable() {
    let dir = crate::test_support::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"old").unwrap();
    let args = arguments(&target, true);
    let session = Session::connect(
        &args,
        args.descriptor_copy
            .as_ref()
            .unwrap()
            .location
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let (reader, _producer) = std::os::unix::net::UnixStream::pair().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let descriptor = fd::Descriptor::owned(
        File::from(std::os::fd::OwnedFd::from(reader)),
        true,
        cancelled.clone(),
    )
    .unwrap();
    let retirement = descriptor.retirement().unwrap();
    let transfer = execute(
        session.clone(),
        args.descriptor_copy.clone().unwrap(),
        controls(&args),
        cancelled.clone(),
        Some(descriptor),
        None,
        None,
        None,
    );
    let cancel = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        cancelled.store(true, Relaxed);
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (result, ()) = tokio::join!(transfer, cancel);
        assert!(format!("{:#}", result.unwrap_err()).contains("cancelled"));
        retirement.wait().await;
    })
    .await
    .expect("quiet payload cancellation must retire workers");
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    copy(session, &target, true, &input(b"next"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"next");
}
