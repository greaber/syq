//! Human output must not change the outcome of a filesystem operation.
//! These writes can still block; they deliberately do not buffer or drop slow output.

use std::fmt::Arguments;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Mutex;

/// One lock owns both the live row and writes that can disturb it. Diagnostic
/// writers never take a Progress lock, so worker warnings cannot invert the
/// ticker's lock order. Redirected stdout stays outside this lock.
static TERMINAL: Mutex<Terminal> = Mutex::new(Terminal { line: None });

#[derive(Default)]
pub(crate) struct Terminal {
    line: Option<String>,
}

impl Terminal {
    pub(crate) fn draw(&mut self, out: &mut impl Write, line: String) -> io::Result<()> {
        if self.line.as_ref() != Some(&line) {
            out.write_all(format!("\r{line}\x1b[K").as_bytes())?;
            out.flush()?;
            self.line = Some(line);
        }
        Ok(())
    }

    fn clear(&mut self, out: &mut impl Write) -> io::Result<()> {
        if self.line.take().is_some() {
            out.write_all(b"\r\x1b[2K")?;
            out.flush()?;
        }
        Ok(())
    }

    fn diagnostic(&mut self, out: &mut impl Write, args: Arguments<'_>) -> io::Result<()> {
        let line = self.line.clone();
        self.clear(out)?;
        writeln!(out, "{args}")?;
        if let Some(line) = line {
            self.draw(out, line)?;
        }
        out.flush()
    }
}

pub(crate) fn draw_progress(line: String) {
    let _ = TERMINAL
        .lock()
        .unwrap()
        .draw(&mut io::stderr().lock(), line);
}

pub(crate) fn clear_progress() {
    let _ = TERMINAL.lock().unwrap().clear(&mut io::stderr().lock());
}

pub(crate) fn finish_progress() {
    let mut terminal = TERMINAL.lock().unwrap();
    if terminal.line.take().is_some() {
        let _ = writeln!(io::stderr().lock());
    }
}

pub(crate) fn emit_diagnostic(args: Arguments<'_>) {
    let _ = TERMINAL
        .lock()
        .unwrap()
        .diagnostic(&mut io::stderr().lock(), args);
}

pub(crate) fn emit_human_stdout(args: Arguments<'_>) {
    if let Err(error) = write_stdout(args) {
        warn_stdout(&error);
    }
}

/// Essential output (such as a receipt frame or detach handoff) must let
/// its caller handle failure. The stdout lock is released before returning.
pub(crate) fn write_stdout(args: Arguments<'_>) -> io::Result<()> {
    // A full pipe must not freeze stderr progress or diagnostics.
    if !io::stdout().is_terminal() {
        let mut out = io::stdout().lock();
        return writeln!(out, "{args}").and_then(|()| out.flush());
    }
    let mut terminal = TERMINAL.lock().unwrap();
    let _ = terminal.clear(&mut io::stderr().lock());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_get_a_clean_row_and_restore_the_bar() {
        let mut terminal = Terminal::default();
        let mut output = Vec::new();
        let bar = "[========= ]  93%";
        terminal.draw(&mut output, bar.into()).unwrap();
        terminal
            .diagnostic(&mut output, format_args!("syq: warning: broken pipe"))
            .unwrap();
        terminal
            .diagnostic(&mut output, format_args!("syq: worker connection lost"))
            .unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), format!(
            "\r{bar}\x1b[K\r\x1b[2Ksyq: warning: broken pipe\n\r{bar}\x1b[K\r\x1b[2Ksyq: worker connection lost\n\r{bar}\x1b[K"));
        assert_eq!(terminal.line.as_deref(), Some(bar));
    }
}
