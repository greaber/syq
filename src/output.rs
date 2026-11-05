//! Human output must not change the outcome of a filesystem operation.
//! These writes can still block; they deliberately do not buffer or drop slow
//! output. Output that fails to write, as to a closed pipe, is dropped.

use std::fmt::Arguments;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Mutex;

/// Escape text from names or peer diagnostics without allowing terminal control.
/// Human messages may contain our own line breaks and tabs for layout.
fn safe_message(args: Arguments<'_>) -> String {
    let mut result = String::new();
    for ch in args.to_string().chars() {
        if (ch.is_control() && !matches!(ch, '\n' | '\t'))
            || matches!(ch, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            result.extend(ch.escape_default());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Whether `SYQ_DEBUG` asks for internal diagnostics on stderr.
pub fn debug() -> bool {
    std::env::var_os("SYQ_DEBUG").is_some()
}

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
        self.write_line(out, format_args!("{}", safe_message(args)))
    }

    fn write_line(&mut self, out: &mut impl Write, args: Arguments<'_>) -> io::Result<()> {
        let line = self.line.clone();
        self.clear(out)?;
        // Helpers can inherit the same stderr pipe but have their own locks.
        // Keep the newline in the same write as the message so lines within
        // PIPE_BUF cannot be interleaved by those other processes.
        out.write_all(format!("{args}\n").as_bytes())?;
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
    if let Err(error) = write_stdout(format_args!("{}", safe_message(args))) {
        warn_stdout(&error);
    }
}

/// Essential output (such as a relayed results line or detach handoff) must let
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

/// Set once stdout's reader has gone away, as `head` does after its lines:
/// a command's later output to stdout is dropped without trying.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
/// Set once a command's output could not be written for another reason, as
/// to a full disk: the failure has been reported, later output is dropped,
/// and `exit` fails the command.
static STDOUT_FAILED: AtomicBool = AtomicBool::new(false);

pub(crate) fn warn_stdout(error: &io::Error) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Relaxed) {
        emit_diagnostic(format_args!(
            "syq: warning: could not write human output to stdout: {error}"
        ));
    }
}

fn command_stdout_lost() -> bool {
    STDOUT_CLOSED.load(Relaxed) || STDOUT_FAILED.load(Relaxed)
}

/// Print a command's own output as written, such as `--version`, a listing
/// or JSON. As coreutils do, a closed stdout ends the output quietly, as
/// when piped into `head`: the reader has what it wanted. Any other write
/// failure, as to a full disk, is reported once and fails the command when
/// it exits (`exit`), so truncated output never looks complete. A copy's
/// human output (`human_stdout!`) instead only warns.
pub(crate) fn emit_command_stdout(args: Arguments<'_>) {
    if command_stdout_lost() {
        return;
    }
    let mut out = io::stdout().lock();
    if let Err(error) = out.write_fmt(args).and_then(|()| out.flush()) {
        command_stdout_failed(&error);
    }
}

/// A command's own human output, escaped and placed as `human_stdout!`
/// does, with failures handled as `emit_command_stdout` handles them.
pub(crate) fn emit_command_human_stdout(args: Arguments<'_>) {
    if command_stdout_lost() {
        return;
    }
    if let Err(error) = write_stdout(format_args!("{}", safe_message(args))) {
        command_stdout_failed(&error);
    }
}

pub(crate) fn command_stdout_failed(error: &io::Error) {
    if error.kind() == io::ErrorKind::BrokenPipe {
        STDOUT_CLOSED.store(true, Relaxed);
    } else if !STDOUT_FAILED.swap(true, Relaxed) {
        emit_diagnostic(format_args!("syq: cannot write to stdout: {error}"));
    }
}

/// End the process with `code`. A command whose output could not all be
/// written, except to a closed stdout, fails with 1 instead of succeeding.
pub(crate) fn exit(code: i32) -> ! {
    let code = if code == 0 && STDOUT_FAILED.load(Relaxed) {
        1
    } else {
        code
    };
    std::process::exit(code)
}

/// Print a command-line error, help or version from clap, and exit as
/// `Error::exit` does, except that help or a version that could not be
/// written to stdout fails as other command output does.
pub(crate) fn exit_with(error: impl std::borrow::Borrow<clap::Error>) -> ! {
    let error = error.borrow();
    let printed = error.print();
    if !error.use_stderr() {
        if let Err(failure) = printed {
            command_stdout_failed(&failure);
        }
    }
    exit(error.exit_code())
}

/// Stdout for a command that writes its output as a stream. A failure ends
/// the stream: the first is reported as `emit_command_stdout` reports it,
/// and it and every later write return an error, so the command stops
/// through its usual `?` instead of doing work nobody will read; then
/// `exit_on_error` ends it quietly for a closed stdout. Dropping it flushes
/// what it holds.
pub(crate) fn command_stdout() -> CommandStdout {
    CommandStdout(io::stdout().lock())
}

pub(crate) struct CommandStdout(io::StdoutLock<'static>);

/// Set once a command's stdout stream has returned an error: the command's
/// own failure that follows is that end, already handled. Serializers such
/// as serde_json replace the error they were given, so the error itself
/// cannot carry this.
static STREAM_ENDED: AtomicBool = AtomicBool::new(false);

fn stream_ended(error: io::Error) -> io::Error {
    STREAM_ENDED.store(true, Relaxed);
    error
}

impl Write for CommandStdout {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if command_stdout_lost() {
            return Err(stream_ended(io::ErrorKind::BrokenPipe.into()));
        }
        self.0.write(buffer).map_err(|error| {
            command_stdout_failed(&error);
            stream_ended(error)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        if command_stdout_lost() {
            return Err(stream_ended(io::ErrorKind::BrokenPipe.into()));
        }
        self.0.flush().map_err(|error| {
            command_stdout_failed(&error);
            stream_ended(error)
        })
    }
}

impl Drop for CommandStdout {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// End a command that failed with `error`. When its stdout stream ended the
/// command, that end has been handled: a closed stdout exits quietly with 0,
/// as for a reader that stopped early, and another failure, reported when
/// it happened, exits 1. Otherwise print `context: error` and exit with
/// `code`.
pub(crate) fn exit_on_error(error: &anyhow::Error, code: i32, context: &str) -> ! {
    if STREAM_ENDED.load(Relaxed) {
        exit(i32::from(STDOUT_FAILED.load(Relaxed)));
    }
    emit_diagnostic(format_args!("{context}: {error:#}"));
    exit(code)
}

/// Pass another process's human output through to ours. After a write
/// fails, keep reading and drop the rest. Closing the pipe instead would fail
/// the other process's writes, and an OpenSSH client that cannot write a
/// session's stderr stops crediting its flow-control window, which stalls
/// the session once enough stderr arrives. Returns the first write error.
pub(crate) fn pass_through(
    mut input: impl io::Read,
    output: &mut impl Write,
) -> io::Result<Option<io::Error>> {
    let mut buffer = [0; 8192];
    let mut failed = None;
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => return Ok(failed),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if failed.is_none() {
            if let Err(error) = output
                .write_all(&buffer[..count])
                .and_then(|()| output.flush())
            {
                failed = Some(error);
            }
        }
    }
}

macro_rules! command_print {
    ($($arg:tt)*) => { $crate::output::emit_command_stdout(format_args!($($arg)*)) };
}
pub(crate) use command_print;

macro_rules! command_human_stdout {
    ($($arg:tt)*) => { $crate::output::emit_command_human_stdout(format_args!($($arg)*)) };
}
pub(crate) use command_human_stdout;

macro_rules! command_println {
    ($($arg:tt)*) => {
        $crate::output::emit_command_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}
pub(crate) use command_println;

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
    fn pass_through_keeps_reading_after_its_output_fails() {
        struct Closed(usize);
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let input = vec![7; 100_000];
        let mut reader = io::Cursor::new(input);
        let mut output = Closed(0);
        let error = pass_through(&mut reader, &mut output).unwrap().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(reader.position(), 100_000, "the writer must be drained");
        assert_eq!(output.0, 1, "output stops at the first failure");

        let mut output = Vec::new();
        let input = b"passed through".as_slice();
        assert!(pass_through(input, &mut output).unwrap().is_none());
        assert_eq!(output, b"passed through");
    }

    #[test]
    fn concurrent_process_diagnostics_do_not_split_lines() {
        // Model another process writing to the same stderr pipe after each
        // write. The in-process terminal lock cannot exclude that writer.
        #[derive(Default)]
        struct SharedPipe(Vec<u8>);
        impl Write for SharedPipe {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(bytes);
                self.0.extend_from_slice(b"syq: helper closed\n");
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut output = SharedPipe::default();
        let mut terminal = Terminal::default();
        let counters = serde_json::json!({"range_requests": 0});
        terminal
            .diagnostic(
                &mut output,
                format_args!("syq: tuning observed: {counters}"),
            )
            .unwrap();
        terminal
            .write_line(&mut output, format_args!("{counters}"))
            .unwrap();
        assert_eq!(
            String::from_utf8(output.0).unwrap(),
            format!("syq: tuning observed: {counters}\nsyq: helper closed\n{counters}\nsyq: helper closed\n")
        );
    }

    #[test]
    fn json_output_preserves_unicode_and_json_escapes() {
        let message = "quote \" slash \\ newline\n control \u{1b} separators \u{2028}\u{2029} bidi \u{061c}\u{202e}";
        let warning = serde_json::json!({"type": "warning", "message": message});
        let mut output = Vec::new();
        Terminal::default()
            .write_line(&mut output, format_args!("{warning}"))
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(decoded["message"], message);
        assert_eq!(output.iter().filter(|&&byte| byte == b'\n').count(), 1);
        assert!(!output.contains(&0x1b));
    }

    #[test]
    fn peer_diagnostics_cannot_control_the_terminal() {
        let mut output = Vec::new();
        Terminal::default()
            .diagnostic(
                &mut output,
                format_args!("name: \x1b]52;c;ZXZpbA==\x07\r\u{202e}"),
            )
            .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\x07'));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("\\u{1b}]52"));
    }

    #[test]
    fn human_messages_escape_unicode_separators_and_directional_marks() {
        let text = safe_message(format_args!(
            "a\u{061c}\u{200e}\u{200f}\u{2028}\u{2029}z\n\t"
        ));
        assert_eq!(text, "a\\u{61c}\\u{200e}\\u{200f}\\u{2028}\\u{2029}z\n\t");
    }

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
