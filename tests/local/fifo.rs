use super::*;

/// The test process never opens a FIFO reader. In particular, it must not
/// supply an extra reader that another parallel test could inherit at fork.
struct WaitingWriter {
    child: std::process::Child,
    connected: PathBuf,
}

impl WaitingWriter {
    fn start(t: &Tmp, fifo: &Path) -> Self {
        let ready = t.path("writer-ready");
        let connected = t.path("writer-connected");
        let child = Command::new("sh")
            .args([
                "-c",
                ": > \"$2\"; exec 3>\"$1\"; : > \"$3\"; printf payload >&3",
                "fifo-producer",
            ])
            .arg(fifo)
            .arg(&ready)
            .arg(&connected)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .start()
            .unwrap();
        let mut writer = Self { child, connected };
        wait_for_confinement_marker(&mut writer.child, &ready, "FIFO producer startup");
        // Allow the producer to enter its blocking open after the marker.
        writer.assert_waiting();
        writer
    }

    fn assert_waiting(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !self.connected.exists(),
            "metadata inspection connected the FIFO producer"
        );
        assert!(self.child.try_wait().unwrap().is_none(), "producer exited");
    }
}

impl Drop for WaitingWriter {
    fn drop(&mut self) {
        // This shell uses only builtins and owns a separate process group.
        let group = -(self.child.id() as i32);
        if self
            .child
            .try_wait()
            .expect("inspect FIFO producer")
            .is_none()
        {
            unsafe { libc::kill(group, libc::SIGKILL) };
        }
        self.child.wait().expect("reap FIFO producer");
        let result = unsafe { libc::kill(group, 0) };
        let error = std::io::Error::last_os_error();
        assert!(result == -1 && error.raw_os_error() == Some(libc::ESRCH));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn rejected_control_fifos_do_not_connect_a_producer() {
    for option in ["--ignore-from", "--mapping", "--files-from"] {
        let t = Tmp::new();
        let fifo = t.path("pipe");
        mkfifo(&fifo);
        write(&t.path("src/file"), b"data");
        let mut writer = WaitingWriter::start(&t, &fifo);
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        if option == "--files-from" {
            command
                .args(["rsync", "-a", option])
                .arg(&fifo)
                .arg(t.path("src"))
                .arg(t.path("dst"));
        } else {
            command.args(["cp", option]).arg(&fifo);
            if option == "--ignore-from" {
                command.arg("--srcs-in").arg(t.path("src"));
            }
            command.arg("--into").arg(t.path("dst"));
        }
        let output = command.run().unwrap();
        assert!(!output.status.success(), "{option}");
        assert!(
            stderr_of(&output).contains("exact descriptor"),
            "{}",
            stderr_of(&output)
        );
        assert!(!t.path("dst").exists());
        writer.assert_waiting();
    }
}

#[cfg(debug_assertions)]
#[test]
fn replaced_control_fifo_does_not_connect_a_producer() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"data");
    let selected = t.path("rules");
    write(&selected, b"# no exclusions\n");
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--ignore-from"])
        .arg(&selected)
        .arg("--srcs-in")
        .arg(t.path("src"))
        .arg("--into")
        .arg(t.path("dst"));
    let mut child = start_held_control_path(&mut command, &selected, &ready, &continuation);
    wait_for_control_path_selection(&mut child, &ready);
    fs::rename(&selected, t.path("original")).unwrap();
    mkfifo(&selected);
    let mut writer = WaitingWriter::start(&t, &selected);
    release_confinement_barrier(&continuation);
    let output = wait_for_control_path_output(child);
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("changed identity"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("dst").exists());
    writer.assert_waiting();
}

#[test]
fn fifo_node_operations_do_not_connect_a_producer() {
    for operation in [
        "map",
        "map-root",
        "remove-preview",
        "copy-node",
        "results",
        "stream-destination",
    ] {
        let t = Tmp::new();
        let fifo = t.path("pipe");
        mkfifo(&fifo);
        write(&t.path("file"), b"data");
        let mut writer = WaitingWriter::start(&t, &fifo);
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        match operation {
            "map" => {
                command
                    .args(["map", "--include", "kind", "-C"])
                    .arg(&t.0)
                    .arg("pipe");
            }
            "map-root" => {
                command
                    .args(["map", "--include", "kind", "--root"])
                    .arg(&t.0)
                    .arg("pipe");
            }
            "remove-preview" => {
                command.args(["rm", "--dry-run"]).arg(&fifo);
            }
            "copy-node" => {
                command
                    .args(["cp", "--copy-metadata=specials"])
                    .arg(&fifo)
                    .arg("--as")
                    .arg(t.path("dst"));
            }
            "results" => {
                command
                    .arg("cp")
                    .arg(t.path("file"))
                    .arg("--as")
                    .arg(t.path("dst"))
                    .arg("--results")
                    .arg(&fifo);
            }
            "stream-destination" => {
                command.args(["cp", "--src-fd", "0", "--as"]).arg(&fifo);
            }
            _ => unreachable!(),
        }
        let output = command.run().unwrap();
        let rejects_fifo = matches!(operation, "results" | "stream-destination");
        assert_eq!(
            output.status.success(),
            !rejects_fifo,
            "{operation}: {}",
            stderr_of(&output)
        );
        if operation.starts_with("map") {
            let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(record["kind"], "special");
            assert_eq!(record["src"]["value"], "pipe");
        }
        if operation == "copy-node" {
            assert!(fs::symlink_metadata(t.path("dst"))
                .unwrap()
                .file_type()
                .is_fifo());
        } else {
            assert!(!t.path("dst").exists());
        }
        assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        writer.assert_waiting();
    }
}

/// Symlinks and special files share one planning path. Pin what it reports
/// for each way the destination can differ, previewed and applied.
#[test]
fn symlink_and_fifo_plans_report_each_destination_state() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    fs::create_dir_all(t.path("dst/src")).unwrap();
    for name in ["new-link", "typed-link", "moved-link"] {
        std::os::unix::fs::symlink("target", t.path(&format!("src/{name}"))).unwrap();
    }
    mkfifo(&t.path("src/new-fifo"));
    mkfifo(&t.path("src/typed-fifo"));
    write(&t.path("dst/src/typed-link"), b"file");
    write(&t.path("dst/src/typed-fifo"), b"file");
    std::os::unix::fs::symlink("old-target", t.path("dst/src/moved-link")).unwrap();
    let copy = |extra: &[&str]| {
        let mut args = vec!["--copy-metadata=specials", "-v"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["src", "--into", "dst"]);
        syq_cp_in(&t.path(""), &args, None)
    };

    let out = copy(&["-n", "--results", "preview.ndjson"]);
    assert_output_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in [
        "create symlink dst/src/new-link -> target (destination missing)",
        "replace with symlink dst/src/typed-link -> target (destination is regular file)",
        "update symlink dst/src/moved-link -> target (target differs)",
        "create FIFO dst/src/new-fifo (destination missing)",
        "replace with FIFO dst/src/typed-fifo (destination is regular file)",
        "  changes: 3 symlinks; 2 special files; 2 type replacements among them",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line:?} in {stdout}"
        );
    }
    let traces: std::collections::BTreeSet<String> =
        String::from_utf8(read(&t.path("preview.ndjson")))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|v| v["type"] == "trace")
            .map(|v| {
                format!(
                    "{} {} {} {}",
                    v["dst"]["value"], v["action"], v["kind"], v["reason"]
                )
            })
            .collect();
    let expected: std::collections::BTreeSet<String> = [
        r#""src/moved-link" "create_symlink" "symlink" "content_differs""#,
        r#""src/new-fifo" "create_special" "special" "destination_missing""#,
        r#""src/new-link" "create_symlink" "symlink" "destination_missing""#,
        r#""src/typed-fifo" "create_special" "special" "type_differs""#,
        r#""src/typed-link" "create_symlink" "symlink" "type_differs""#,
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(traces, expected);

    let out = copy(&[]);
    assert_output_ok(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in [
        "src/new-link -> target",
        "src/typed-link -> target",
        "src/moved-link -> target",
        "src/new-fifo",
        "src/typed-fifo",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line:?} in {stdout}"
        );
    }
    for name in ["new-fifo", "typed-fifo"] {
        let path = t.path(&format!("dst/src/{name}"));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
    }
    for name in ["new-link", "typed-link", "moved-link"] {
        let path = t.path(&format!("dst/src/{name}"));
        assert_eq!(fs::read_link(&path).unwrap(), Path::new("target"));
    }

    let out = copy(&["--if-exists=error"]);
    assert!(!out.status.success());
    let stderr = stderr_of(&out);
    for line in [
        "syq: destination already exists: dst/src/new-link (--if-exists=error)",
        "syq: destination already exists: dst/src/new-fifo (--if-exists=error)",
    ] {
        assert!(
            stderr.lines().any(|l| l == line),
            "missing {line:?} in {stderr}"
        );
    }
}
