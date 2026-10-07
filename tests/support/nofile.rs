//! Set a precise descriptor limit on a child without changing the test runner.
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn set_child_nofile_limit(command: &mut Command, requested: libc::rlim_t) {
    let mut inherited = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) } != 0 {
        panic!(
            "read inherited descriptor limit: {}",
            std::io::Error::last_os_error()
        );
    }
    assert!(
        inherited.rlim_max >= requested,
        "inherited hard descriptor limit {} is below the test limit {requested}",
        inherited.rlim_max
    );
    let limit = libc::rlimit {
        rlim_cur: requested,
        rlim_max: requested,
    };
    unsafe {
        command.pre_exec(move || {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Start the child with only standard input, output and error open, as an
/// SSH session starts its remote command. A test runner can leave
/// inheritable descriptors open in every process it starts, as the macOS CI
/// runners do. The fake remote shell would hand them on to the helper, whose
/// descriptor budget would then depend on the runner rather than on the
/// limit the test sets.
#[allow(dead_code)]
pub fn inherit_only_standard_descriptors(command: &mut Command) {
    let inherited: Vec<libc::c_int> = std::fs::read_dir("/proc/self/fd")
        .or_else(|_| std::fs::read_dir("/dev/fd"))
        .expect("list this process's descriptors")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&descriptor| descriptor > 2)
        .collect();
    unsafe {
        command.pre_exec(move || {
            for &descriptor in &inherited {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
}
