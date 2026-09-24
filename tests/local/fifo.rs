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
                    .args(["cp", "--preserve=specials"])
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
