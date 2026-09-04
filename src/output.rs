//! Human output must not change the outcome of a filesystem operation.
//! These writes can still block; they deliberately do not buffer or drop slow output.

use std::fmt::Arguments;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

pub(crate) fn emit_diagnostic(args: Arguments<'_>) {
    let _ = writeln!(io::stderr().lock(), "{args}");
}

pub(crate) fn emit_human_stdout(args: Arguments<'_>) {
    if let Err(error) = write_stdout(args) {
        warn_stdout(&error);
    }
}

/// Essential output (such as a receipt frame or detach handoff) must let
/// its caller handle failure. The stdout lock is released before returning.
pub(crate) fn write_stdout(args: Arguments<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{args}").and_then(|()| out.flush())
}

pub(crate) fn warn_stdout(error: &io::Error) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Relaxed) {
        emit_diagnostic(format_args!(
            "syq: warning: could not write human output to stdout: {error}"
        ));
    }
}

macro_rules! diagnostic {
    ($($arg:tt)*) => { $crate::output::emit_diagnostic(format_args!($($arg)*)) };
}
pub(crate) use diagnostic;

macro_rules! human_stdout {
    ($($arg:tt)*) => { $crate::output::emit_human_stdout(format_args!($($arg)*)) };
}
pub(crate) use human_stdout;
