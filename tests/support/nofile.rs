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
