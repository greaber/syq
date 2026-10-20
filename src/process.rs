//! Coordinate process creation and bounded policy-inspection subprocesses.
use std::process::{Child, Command, ExitStatus, Output, Stdio};

#[path = "process_group.rs"]
pub(crate) mod group;

#[path = "process_signals.rs"]
pub(crate) mod signals;

#[path = "process_termination.rs"]
pub(crate) mod termination;

/// Serialize non-atomic close-on-exec setup with child launches on Darwin.
/// The operation must only create/protect descriptors or launch a process;
/// do not hold this guard while waiting for peer I/O or child completion.
pub(crate) fn with_inheritance_guard<T>(operation: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "macos")]
    let _guard = {
        static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SPAWN.lock().unwrap_or_else(|error| error.into_inner())
    };
    operation()
}

/// A command that runs this same build again, for receivers, services and
/// other internal modes. An upgrade or rebuild can replace the file at the
/// path syq started from while it runs. On Linux, /proc/self/exe still names
/// the running image; the child gets the original path as argv[0], and
/// `restore_self_started_name` gives it the file's name. macOS has no
/// equivalent, so there a path that names another file is refused
/// (`require_started_file`) rather than started.
pub(crate) fn self_command() -> std::io::Result<Command> {
    let path = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    let command = {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt as _;
        let mut command = Command::new(SELF_EXE);
        // Linux reports a replaced or removed file's path with this suffix.
        let path = path.as_os_str().as_bytes();
        let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
        command.arg0(std::ffi::OsStr::from_bytes(path));
        command
    };
    #[cfg(target_os = "macos")]
    let command = {
        require_started_file(&path)?;
        Command::new(path)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let command = Command::new(path);
    Ok(command)
}

/// macOS: refuse to start `path` once it names a file other than the one
/// this process runs, as after an upgrade or rebuild replaced or removed it,
/// since that would start another build. The file this process runs is read
/// from the kernel at the first start, so syq's own startup pays nothing;
/// each start then costs one stat of the path. Where the kernel does not say,
/// the path is started as before.
#[cfg(target_os = "macos")]
fn require_started_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    static RUNNING: std::sync::OnceLock<Option<(u32, u64)>> = std::sync::OnceLock::new();
    let Some(running) = *RUNNING.get_or_init(running_file) else {
        return Ok(());
    };
    match std::fs::metadata(path) {
        // st_dev is 32 bits on macOS; the kernel reports it unsigned.
        Ok(metadata) if (metadata.dev() as u32, metadata.ino()) == running => Ok(()),
        Ok(_) => Err(replaced(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(replaced(path)),
        // Starting it reports anything else.
        Err(_) => Ok(()),
    }
}

#[cfg(target_os = "macos")]
fn replaced(path: &std::path::Path) -> std::io::Error {
    std::io::Error::other(replaced_message(path, SERVICE.get()))
}

/// A long-lived background process, which a user restarts rather than
/// reruns once syq is upgraded under it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum Service {
    /// A receiving connection to this server (`--receive-service`).
    Receiving { endpoint: String },
    /// The local provider service `syq persist receive on` starts.
    Provider,
    /// A persistent connection that `syq persist off` closes and the next
    /// command opens again, named here.
    Connection(&'static str),
}

/// The service this process runs, and its persistence domain's explicit path.
#[cfg(target_os = "macos")]
static SERVICE: std::sync::OnceLock<(Service, Option<std::path::PathBuf>)> =
    std::sync::OnceLock::new();

/// Note that this process runs `service` in the persistence domain at
/// `scope` (`None` for the default one), so that a refused start says how
/// to restart it. Call once, as the service starts.
pub(crate) fn running_service(service: Service, scope: Option<&std::path::Path>) {
    #[cfg(target_os = "macos")]
    let _ = SERVICE.set((service, scope.map(std::path::Path::to_path_buf)));
    #[cfg(not(target_os = "macos"))]
    let _ = (service, scope);
}

/// What a refused start says: a command is rerun, a service restarted with
/// the commands for its kind and domain.
#[cfg(any(target_os = "macos", test))]
fn replaced_message(
    path: &std::path::Path,
    service: Option<&(Service, Option<std::path::PathBuf>)>,
) -> String {
    let Some((service, scope)) = service else {
        return format!(
            "syq at {} was replaced while this command was running; rerun the command",
            path.display()
        );
    };
    let persist = |words: &str| match scope {
        Some(scope) => format!(
            "`syq persist {words} --pscope {}`",
            shell_words::quote(&scope.to_string_lossy())
        ),
        None => format!("`syq persist {words}`"),
    };
    let (name, restart) = match service {
        Service::Receiving { endpoint } => (
            format!("the receiving connection to {endpoint}"),
            format!(
                "restart it with {}, then {}",
                persist("off"),
                persist(&format!("connect {}", shell_words::quote(endpoint)))
            ),
        ),
        Service::Provider => (
            "the local provider service".to_owned(),
            format!("restart it with {}", persist("receive on")),
        ),
        Service::Connection(name) => (
            (*name).to_owned(),
            format!(
                "close it with {}; the next syq command starts the new version",
                persist("off")
            ),
        ),
    };
    format!(
        "syq at {} was upgraded while {name} was running; {restart}",
        path.display()
    )
}

/// macOS: the device and inode of the file this process runs, as the kernel
/// recorded them when it mapped this code, which stay right after that file
/// is replaced or removed.
#[cfg(target_os = "macos")]
fn running_file() -> Option<(u32, u64)> {
    // <sys/proc_info.h>; libc does not declare this flavor.
    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
    #[repr(C)]
    struct RegionInfo {
        protection_inheritance_flags: [u32; 4],
        offset: u64,
        counts: [u32; 14],
        address: u64,
        size: u64,
    }
    #[repr(C)]
    struct RegionWithPathInfo {
        region: RegionInfo,
        vnode: libc::vnode_info_path,
    }
    let address = running_file as *const () as u64;
    let mut info = std::mem::MaybeUninit::<RegionWithPathInfo>::zeroed();
    let size = std::mem::size_of::<RegionWithPathInfo>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    // The kernel returns the region holding the address, or the next one.
    let region = &info.region;
    let stat = &info.vnode.vip_vi.vi_stat;
    (region.address <= address && address - region.address < region.size && stat.vst_ino != 0)
        .then_some((stat.vst_dev, stat.vst_ino))
}

#[cfg(target_os = "linux")]
const SELF_EXE: &str = "/proc/self/exe";

/// A process started through /proc/self/exe is named "exe" in ps and pgrep.
/// Name it after the file in its argv[0], as an ordinary start would. Every
/// syq start runs this check, so it reads the path given to exec from the
/// auxiliary vector, which needs no system call.
#[cfg(target_os = "linux")]
pub(crate) fn restore_self_started_name() {
    use std::os::unix::ffi::OsStrExt;
    let execfn = unsafe { libc::getauxval(libc::AT_EXECFN) } as *const libc::c_char;
    if execfn.is_null()
        || unsafe { std::ffi::CStr::from_ptr(execfn) }.to_bytes() != SELF_EXE.as_bytes()
    {
        return;
    }
    let Some(path) = std::env::args_os().next() else {
        return;
    };
    let Some(name) = std::path::Path::new(&path).file_name() else {
        return;
    };
    // The kernel keeps 15 bytes of a process name.
    let name = name.as_bytes();
    if let Ok(name) = std::ffi::CString::new(&name[..name.len().min(15)]) {
        unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
    }
}

pub(crate) trait CommandExt {
    fn spawn_guarded(&mut self) -> std::io::Result<Child>;
    fn status_guarded(&mut self) -> std::io::Result<ExitStatus>;
    /// Capture both outputs with null stdin. For custom stdio, configure it
    /// explicitly and use spawn_guarded followed by wait_with_output instead.
    fn capture_output(&mut self) -> std::io::Result<Output>;
}

impl CommandExt for Command {
    fn spawn_guarded(&mut self) -> std::io::Result<Child> {
        with_inheritance_guard(|| self.spawn())
    }

    fn status_guarded(&mut self) -> std::io::Result<ExitStatus> {
        self.spawn_guarded()?.wait()
    }

    fn capture_output(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_guarded()?
            .wait_with_output()
    }
}

/// Run an inspection command under one deadline, including descendants that
/// retain its output pipes. Neither output nor cancellation needs a reader
/// thread whose lifetime can outlast the command's process group.
pub(crate) fn capture_output_bounded(
    command: &mut Command,
    deadline: std::time::Instant,
    cancelled: &dyn Fn() -> bool,
    max_output_bytes: usize,
) -> std::io::Result<Output> {
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::{Duration, Instant};

    fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SSH policy inspection cancelled",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH policy inspection timed out",
            ));
        }
        Ok(())
    }
    fn nonblocking(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn drain(
        reader: &mut impl Read,
        output: &mut Vec<u8>,
        total: &mut usize,
        limit: usize,
    ) -> io::Result<bool> {
        let mut buffer = [0; 16 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => Ok(true),
            Ok(count) => {
                if count > limit.saturating_sub(*total) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH policy inspection output exceeds its byte limit",
                    ));
                }
                *total += count;
                output.extend_from_slice(&buffer[..count]);
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    check(deadline, cancelled)?;
    let mut group = group::ProcessGroup::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?;
    let mut stdout = group.child.stdout.take().unwrap();
    let mut stderr = group.child.stderr.take().unwrap();
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_done, mut err_done) = (false, false);
    let mut total = 0;
    loop {
        check(deadline, cancelled)?;
        if !out_done {
            out_done = drain(&mut stdout, &mut out, &mut total, max_output_bytes)?;
        }
        if !err_done {
            err_done = drain(&mut stderr, &mut err, &mut total, max_output_bytes)?;
        }
        // Keep the leader unreaped until its descendants have closed the
        // pipes, then let ProcessGroup stop remaining descendants before
        // reaping. The process-group identifier stays reserved until cleanup.
        if out_done && err_done {
            match group.poll() {
                Ok(Some(status)) => {
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        let mut descriptors = [
            libc::pollfd {
                fd: if out_done { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if err_done { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20))
            .as_millis() as i32;
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt as _;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn descriptor_creation_excludes_child_launch() {
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (child, _pipes) = with_inheritance_guard(|| {
            // Model the interval between pipe() and fcntl(FD_CLOEXEC).
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let pipes = fds.map(|fd| unsafe { std::fs::File::from_raw_fd(fd) });
            let child = std::thread::spawn(move || {
                let mut command = Command::new("/usr/bin/true");
                unsafe {
                    command.pre_exec(move || {
                        for fd in fds {
                            if libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC == 0 {
                                return Err(std::io::Error::from_raw_os_error(libc::EBADF));
                            }
                        }
                        Ok(())
                    });
                }
                started_tx.send(()).unwrap();
                let result = command.spawn_guarded();
                finished_tx.send(result.is_ok()).unwrap();
                result.unwrap().wait().unwrap()
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let blocked = finished_rx.recv_timeout(Duration::from_millis(100));
            for fd in fds {
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
            assert_eq!(blocked, Err(mpsc::RecvTimeoutError::Timeout));
            (child, pipes)
        });
        assert!(finished_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        assert!(child.join().unwrap().success());
    }

    /// The kernel's record of the running file is this test binary, so its
    /// own path may start, and another file or a missing one may not.
    #[test]
    fn only_the_running_file_starts() {
        use std::os::unix::fs::MetadataExt;
        let executable = std::env::current_exe().unwrap();
        let metadata = std::fs::metadata(&executable).unwrap();
        assert_eq!(
            running_file(),
            Some((metadata.dev() as u32, metadata.ino()))
        );
        require_started_file(&executable).unwrap();
        let directory = crate::test_support::tempdir().unwrap();
        let other = directory.path().join("syq");
        std::fs::write(&other, b"another build").unwrap();
        for path in [other.clone(), directory.path().join("missing")] {
            let error = require_started_file(&path).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("was replaced while this command was running"),
                "{error}"
            );
        }
    }
}

/// A refused start tells a command to rerun and a service how to restart.
#[cfg(test)]
mod replaced_message_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn commands_rerun_and_services_name_their_restart() {
        let path = Path::new("/opt/syq/bin/syq");
        let message = |service: Service, scope: Option<&str>| {
            replaced_message(path, Some(&(service, scope.map(PathBuf::from))))
        };
        assert_eq!(
            replaced_message(path, None),
            "syq at /opt/syq/bin/syq was replaced while this command was running; \
             rerun the command"
        );
        assert_eq!(
            message(
                Service::Receiving {
                    endpoint: "alice@server".into()
                },
                None
            ),
            "syq at /opt/syq/bin/syq was upgraded while the receiving connection to \
             alice@server was running; restart it with `syq persist off`, then \
             `syq persist connect alice@server`"
        );
        assert_eq!(
            message(Service::Provider, Some("/tmp/my scope")),
            "syq at /opt/syq/bin/syq was upgraded while the local provider service was \
             running; restart it with `syq persist receive on --pscope '/tmp/my scope'`"
        );
        assert_eq!(
            message(Service::Connection("the session pool"), None),
            "syq at /opt/syq/bin/syq was upgraded while the session pool was running; \
             close it with `syq persist off`; the next syq command starts the new version"
        );
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn capture(
        script: &str,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        limit: usize,
    ) -> std::io::Result<Output> {
        capture_output_bounded(
            Command::new("sh").args(["-c", script]),
            Instant::now() + timeout,
            cancelled,
            limit,
        )
    }

    #[test]
    fn captures_both_outputs_and_exit_status() {
        let output = capture(
            "printf output; printf error >&2; exit 17",
            Duration::from_secs(5),
            &|| false,
            64,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(output.stdout, b"output");
        assert_eq!(output.stderr, b"error");
    }

    #[test]
    fn deadline_kills_descendant_holding_output_after_parent_exits() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt as _;
        // The shell and everything it starts inherit this pipe as descriptor
        // 3, so its read end reaches EOF only once all of them have exited.
        // A PID file would need the shell to write it before the deadline,
        // which a slow host does not guarantee.
        let (mut alive, holder) = with_inheritance_guard(std::io::pipe).unwrap();
        let fd = holder.as_raw_fd();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & exit 0"]);
        unsafe {
            command.pre_exec(move || {
                // dup2 clears close-on-exec on its copy; dup2(3, 3) does not.
                let result = if fd == 3 {
                    libc::fcntl(fd, libc::F_SETFD, 0)
                } else {
                    libc::dup2(fd, 3)
                };
                if result < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let error = capture_output_bounded(
            &mut command,
            Instant::now() + Duration::from_millis(150),
            &|| false,
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(holder);
        let (closed, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || closed.send(alive.read_to_end(&mut Vec::new()).unwrap()));
        let unread = wait
            .recv_timeout(Duration::from_secs(3))
            .expect("inspection descendant survived process-group cleanup");
        assert_eq!(unread, 0);
    }

    #[test]
    fn normal_completion_stops_descendant_without_output_pipes() {
        let output = capture(
            "sleep 30 </dev/null >/dev/null 2>&1 & echo $!; exit 17",
            Duration::from_secs(5),
            &|| false,
            1024,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(17));
        let pid = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_descendant_stopped(pid);
    }

    fn assert_descendant_stopped(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            // A container's PID 1 may defer reaping an adopted zombie. It has
            // already exited and cannot retain pipes or execute Match exec.
            #[cfg(target_os = "linux")]
            if std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, fields)| fields.starts_with("Z "))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "inspection descendant survived process-group cleanup"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn cancellation_interrupts_a_stalled_process() {
        let started = Instant::now();
        let error = capture(
            "exec sleep 30",
            Duration::from_secs(10),
            &|| started.elapsed() >= Duration::from_millis(100),
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn output_limit_stops_a_continuously_writing_process() {
        let error = capture(
            "while :; do printf 0123456789abcdef; done",
            Duration::from_secs(5),
            &|| false,
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("byte limit"));
    }
}
