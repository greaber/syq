//! Copies between an SSH server and a bucket, typed on a third machine. That
//! machine starts the copy on the server and signs its storage requests. A
//! stand-in for ssh runs the server's command here without this machine's
//! storage credentials, so every request that reaches the fixture must be a
//! URL this machine signed.
use super::*;

const OBJECT: &[u8] = b"an object for the server\n";

/// `fault` is `from-server-<case>:<directory>`. Uploaded bodies are kept in
/// the directory under their keys' last segments; `request-log` there lists
/// every request.
pub(super) fn serve(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let (case, directory) = fault.split_once(':').unwrap();
    let directory = Path::new(directory);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    {
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join("request-log"))
            .unwrap();
        // One write, so that concurrent requests keep their own lines.
        log.write_all(format!("{method} {path}\n").as_bytes())
            .unwrap();
    }
    // The server holds no credentials: it can only send what was signed.
    assert!(
        !headers.contains_key("authorization"),
        "{method} {target}: the server signed a request itself"
    );
    let field = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
    };
    assert!(
        field("X-Amz-Signature").is_some(),
        "{method} {target}: not a signed URL"
    );
    let expires: u64 = field("X-Amz-Expires").unwrap().parse().unwrap();
    assert!(
        (23 * 60 * 60..=24 * 60 * 60).contains(&expires),
        "signed for {expires} seconds"
    );
    // The command's header reached the server over the signing session.
    assert_eq!(
        headers.get("x-tigris-consistent").map(String::as_str),
        Some("true")
    );
    let fields = vec![
        ("ETag".to_owned(), "\"fixture\"".to_owned()),
        (
            "Last-Modified".to_owned(),
            "Wed, 01 Jan 2020 00:00:00 GMT".to_owned(),
        ),
    ];
    match method {
        "HEAD" if path == "/bucket/stored/object" => {
            let mut fields = fields;
            fields.push(("Content-Length".into(), OBJECT.len().to_string()));
            reply(socket, 200, &fields, b"", true)
        }
        "HEAD" => reply(socket, 404, &[], b"", true),
        "GET" if query.contains("list-type=2") => reply(
            socket,
            200,
            &[],
            b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
            false,
        ),
        "GET" => {
            assert_eq!(path, "/bucket/stored/object");
            reply(socket, 200, &fields, OBJECT, false)
        }
        "PUT" => {
            let length: usize = headers["content-length"].parse().unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            if case == "from-server-hold" {
                // Say an upload is in flight, and keep it there.
                gate.0.store(true, Ordering::Release);
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !gate.1.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                return;
            }
            // A key ending in a slash marks a directory.
            if let Some(name) = path.rsplit('/').next().filter(|name| !name.is_empty()) {
                std::fs::write(directory.join(name), body).unwrap();
            }
            reply(socket, 200, &fields, b"", false)
        }
        _ => panic!("unexpected {method} {target}"),
    }
}

struct Lab {
    temp: tempfile::TempDir,
    server: Server,
}

impl Lab {
    fn start(case: &str) -> Self {
        let temp = crate::test_support::tempdir().unwrap();
        let stored = temp.path().join("stored-by-fixture");
        std::fs::create_dir(&stored).unwrap();
        let fault = format!("from-server-{case}:{}", stored.display());
        // Stands in for ssh: drops its options and the host, then runs the
        // command as the server would, with no storage credentials and its
        // process ID on record.
        executable::write_executable(
            &temp.path().join("bin/ssh"),
            br#"#!/bin/sh
if [ -n "${LAB_SSH_FAILS:-}" ]; then
    echo 'ssh: connect to host server: refused' >&2
    exit 255
fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        -O) exit 1 ;;
        -o|-l|-p|-S) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
cd "$LAB_SERVER_HOME" || exit 1
echo "$$" > "$LAB_SERVER_HOME/copy.pid"
exec /bin/sh -c "$1"
"#,
            0o755,
        );
        std::fs::create_dir_all(temp.path().join("server-home/dataset/sub")).unwrap();
        std::fs::write(temp.path().join("server-home/dataset/a"), b"first\n").unwrap();
        std::fs::write(temp.path().join("server-home/dataset/sub/b"), b"second\n").unwrap();
        Self {
            server: Server::start(Box::leak(fault.into_boxed_str())),
            temp,
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.temp.path().join(name)
    }
    fn command(&self, program: &Path) -> Command {
        self.command_at(program, &self.server.address)
    }
    fn command_at(&self, program: &Path, endpoint: &str) -> Command {
        let mut command = self.server.command(self.temp.path());
        command
            .args(["--s3-endpoint", endpoint])
            .args(["--rsh", self.path("bin/ssh").to_str().unwrap()])
            .args(["--syq-path", program.to_str().unwrap()])
            .env("LAB_SERVER_HOME", self.path("server-home"));
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command(Path::new(env!("CARGO_BIN_EXE_syq")))
            .args(args)
            .capture_output()
            .unwrap()
    }
    fn requests(&self) -> String {
        std::fs::read_to_string(self.path("stored-by-fixture/request-log")).unwrap_or_default()
    }
}

const UPLOAD: &[&str] = &[
    "--from",
    "server",
    "--srcs-in",
    "dataset",
    "--to",
    "s3://bucket",
    "--into",
    "backup",
];

#[test]
fn a_server_uploads_with_urls_this_machine_signed() {
    let lab = Lab::start("ok");
    let output = lab.run(&[UPLOAD, &["--results", "results.jsonl"]].concat());
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        std::fs::read(lab.path("stored-by-fixture/a")).unwrap(),
        b"first\n"
    );
    assert_eq!(
        std::fs::read(lab.path("stored-by-fixture/b")).unwrap(),
        b"second\n"
    );
    let requests = lab.requests();
    assert!(requests.contains("PUT /bucket/backup/a"), "{requests}");
    assert!(requests.contains("PUT /bucket/backup/sub/b"), "{requests}");
    // The server's results and summary arrive here, and say where it ran.
    let text = output_text(&output);
    assert!(text.contains("Copied 2 files"), "{text}");
    assert!(
        text.contains("this machine signs its storage requests"),
        "{text}"
    );
    let results = parsed_results(lab.temp.path());
    let endpoints = results[0]["endpoints"].as_array().unwrap();
    assert!(endpoints
        .iter()
        .any(|e| e["kind"] == "ssh" && e["host"] == "server"));
    assert!(endpoints
        .iter()
        .any(|e| e["kind"] == "s3" && e["host"] == "s3://bucket"));
    let last = results.last().unwrap();
    assert_eq!(
        (&last["status"], &last["files_transferred"]),
        (&"success".into(), &2.into())
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r["type"] == "operation_result" && r["action"] == "transfer_file")
            .count(),
        2
    );
}

/// Named sources are signed for at their own names in the destination
/// directory and nowhere else in it, so the copy must look only there:
/// a request for the directory itself would end it.
#[test]
fn named_sources_upload_within_the_paths_their_names_produce() {
    let lab = Lab::start("ok");
    std::fs::write(lab.path("server-home/note.txt"), b"note\n").unwrap();
    for options in [&[][..], &["--prune", "--max-delete=0"]] {
        let output = lab.run(
            &[
                &["--from", "server", "dataset", "note.txt"],
                &["--to", "s3://bucket", "--into", "backup"],
                options,
            ]
            .concat(),
        );
        assert!(
            output.status.success(),
            "{options:?}: {}",
            output_text(&output)
        );
        assert_eq!(
            std::fs::read(lab.path("stored-by-fixture/note.txt")).unwrap(),
            b"note\n"
        );
        let requests = lab.requests();
        for request in [
            "PUT /bucket/backup/dataset/a",
            "PUT /bucket/backup/dataset/sub/b",
            "PUT /bucket/backup/note.txt",
        ] {
            assert!(requests.contains(request), "{options:?}: {requests}");
        }
    }
}

#[test]
fn a_server_downloads_with_urls_this_machine_signed() {
    let lab = Lab::start("ok");
    let output = lab.run(&[
        "--from",
        "s3://bucket",
        "stored/object",
        "--to",
        "server",
        "--into",
        "restored",
    ]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        std::fs::read(lab.path("server-home/restored/object")).unwrap(),
        OBJECT
    );
    // Nothing was copied to the machine that typed the command.
    assert!(!lab.path("restored").exists());
}

#[test]
fn a_dry_run_signs_and_sends_no_write() {
    let lab = Lab::start("ok");
    let output = lab.run(&[UPLOAD, &["--dry-run", "--prune"]].concat());
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("Would copy 2 files"));
    let requests = lab.requests();
    assert!(!requests.is_empty());
    assert!(
        requests
            .lines()
            .all(|line| line.starts_with("GET ") || line.starts_with("HEAD ")),
        "{requests}"
    );
}

#[test]
fn a_server_asking_beyond_the_command_gets_nothing_signed() {
    let lab = Lab::start("ok");
    // A server that copies into another prefix than the command names:
    // "secrets" in place of the last word, the destination.
    let wrapper = lab.path("bin/other-prefix");
    executable::write_executable(
        &wrapper,
        format!(
            "#!/bin/sh\ncount=$#\nindex=0\nfor word do\n  index=$((index + 1))\n  if [ \"$index\" -eq \"$count\" ]; then set -- \"$@\" c2VjcmV0cw; else set -- \"$@\" \"$word\"; fi\n  shift\ndone\nexec {} \"$@\"\n",
            env!("CARGO_BIN_EXE_syq")
        ),
        0o755,
    );
    let output = lab.command(&wrapper).args(UPLOAD).capture_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
    let text = output_text(&output);
    assert!(
        text.contains("syq: refused to sign a storage request from the server: storage operation is outside the approved permissions"),
        "{text}"
    );
    assert_eq!(lab.requests(), "", "a request reached storage");
    assert!(!lab.path("stored-by-fixture/a").exists());
}

#[test]
fn another_build_on_the_server_is_refused_before_anything_is_signed() {
    let lab = Lab::start("ok");
    // A server whose syq says it is another build.
    let wrapper = lab.path("bin/other-build");
    executable::write_executable(
        &wrapper,
        format!(
            "#!/bin/sh\nSYQ_INTERNAL_NATIVE_STORAGE_SIGNING=v0.0.1-other\nexport SYQ_INTERNAL_NATIVE_STORAGE_SIGNING\nexec {} \"$@\"\n",
            env!("CARGO_BIN_EXE_syq")
        ),
        0o755,
    );
    let output = lab.command(&wrapper).args(UPLOAD).capture_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("needs the same syq build on both machines"),
        "{}",
        output_text(&output)
    );
    assert_eq!(lab.requests(), "");
}

#[test]
fn a_server_that_cannot_reach_storage_says_what_to_check() {
    let lab = Lab::start("ok");
    // An address nothing listens on: this machine signs for it without
    // contacting it, and only the server tries to.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let output = lab
        .command_at(Path::new(env!("CARGO_BIN_EXE_syq")), &address)
        .args(UPLOAD)
        .capture_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
    let text = output_text(&output);
    assert!(
        text.contains(&format!(
            "this server got no answer from the storage service at {address}"
        )) && text.contains("never through the machine that started the copy"),
        "{text}"
    );
    assert_eq!(lab.requests(), "");
}

#[test]
fn missing_credentials_here_fail_the_copy_without_starting_transfers() {
    let lab = Lab::start("ok");
    let output = lab
        .command(Path::new(env!("CARGO_BIN_EXE_syq")))
        .args(UPLOAD)
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .capture_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("this machine's credentials"),
        "{}",
        output_text(&output)
    );
    assert_eq!(lab.requests(), "");
}

#[test]
fn a_failed_ssh_command_does_not_wait_for_slow_credentials() {
    let lab = Lab::start("ok");
    // Credentials that take much longer to arrive than ssh takes to fail.
    let helper = lab.path("bin/slow-credentials");
    executable::write_executable(&helper, "#!/bin/sh\nexec sleep 20\n", 0o755);
    std::fs::write(
        lab.path("aws-config"),
        format!(
            "[profile slow]\ncredential_process = {}\n",
            helper.display()
        ),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let output = lab
        .command(Path::new(env!("CARGO_BIN_EXE_syq")))
        .args(["--s3-profile", "slow"])
        .args(UPLOAD)
        .env("LAB_SSH_FAILS", "1")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env("AWS_CONFIG_FILE", lab.path("aws-config"))
        .capture_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "waited {:?} for credentials",
        started.elapsed()
    );
    let text = output_text(&output);
    assert!(
        text.contains("refused") && text.contains("exit 255"),
        "{text}"
    );
    assert_eq!(lab.requests(), "");
}

#[test]
fn ending_the_command_stops_the_copy_on_the_server() {
    let lab = Lab::start("hold");
    let mut child = lab
        .command(Path::new(env!("CARGO_BIN_EXE_syq")))
        .args(UPLOAD)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let wait = |what: &str, done: &dyn Fn() -> bool| {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            thread::sleep(Duration::from_millis(10));
        }
    };
    // The server is uploading, with every URL it needs already signed.
    wait("an upload in flight", &|| {
        lab.server.gate.0.load(Ordering::Acquire)
    });
    let server_copy: i32 = std::fs::read_to_string(lab.path("server-home/copy.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        unsafe { libc::kill(server_copy, 0) },
        0,
        "the copy is not running"
    );
    // The command ends without a chance to tell the server anything.
    child.kill().unwrap();
    child.wait().unwrap();
    wait("the server's copy to stop", &|| {
        (unsafe { libc::kill(server_copy, 0) }) != 0
    });
    lab.server.gate.1.store(true, Ordering::Release);
    assert!(!lab.path("stored-by-fixture/a").exists());
}

#[test]
fn options_these_copies_cannot_honor_are_refused() {
    let lab = Lab::start("ok");
    for (options, message) in [
        (&["--detach"][..], "--detach is not supported for copies between an SSH server and S3"),
        (&["--auth-from", "ssh"], "S3 authorization requires --auth-from @NAME"),
        (&["--mapping", "manifest"], "--mapping and --stream-mapping-fd are not supported for copies between an SSH server and S3"),
        (&["--coordinate-at", "dst"], "--coordinate-at is not supported for S3 copies"),
        (&["--peer-auth", "broker"], "--peer-auth is not supported for S3 copies"),
        (&["--no-tcp"], "--no-tcp is not supported for S3 copies"),
        (&["--in-place=new"], "--in-place is not supported for S3 copies"),
    ] {
        let output = lab.run(&[options, UPLOAD].concat());
        assert_eq!(output.status.code(), Some(2), "{options:?}: {}", output_text(&output));
        assert!(output_text(&output).contains(message), "{options:?}: {}", output_text(&output));
    }
    for (endpoints, message) in [
        (
            &[
                "--from",
                "@laptop",
                "x",
                "--to",
                "s3://bucket",
                "--into",
                "y",
            ][..],
            "S3 copies cannot use receiving machine @laptop",
        ),
        (
            &[
                "--from",
                "s3://bucket",
                "x",
                "--to",
                "@laptop",
                "--into",
                "y",
            ],
            "S3 copies cannot use receiving machine @laptop",
        ),
    ] {
        let output = lab.run(endpoints);
        assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
        assert!(
            output_text(&output).contains(message),
            "{}",
            output_text(&output)
        );
    }
    assert_eq!(lab.requests(), "");
}
