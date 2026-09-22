"""Managed payload streams. Payload bytes never enter the results decoder."""
from __future__ import annotations

import asyncio
import math
import json
import os
import signal
import subprocess
import threading
from collections.abc import Awaitable, Callable, Mapping

from ._paths import PathArgument
from .errors import SyqInvocationError, SyqProcessError, SyqProtocolError
from .models import CpResult
from .protocol import AutomationDecoder

Argument = str | bytes


def arguments(*, executable: str, writing: bool, path: PathArgument | None,
              endpoint: str | None, options: Mapping[str, object]) -> list[Argument]:
    from .client import _append_path_option, _argument, _text_arg, _warn_unsupported_copy_options
    argv: list[Argument] = [executable, "cp"]
    if writing:
        argv += ["--src-fd", "0"]
        if endpoint is not None:
            argv += ["--to", _text_arg(endpoint, label="to")]
        placements = [("as", path), ("as-new", options.get("as_new")),
                      ("as-existing", options.get("as_existing"))]
        selected = [(name, value) for name, value in placements if value is not None]
        if len(selected) != 1:
            raise SyqInvocationError("open_writer requires exactly one of as_, as_new, or as_existing")
        name, value = selected[0]
        _append_path_option(argv, "--" + name, _argument(value, label=name))
    else:
        if options.get("cwd") is not None and options.get("root") is not None:
            raise SyqInvocationError("cwd and root are mutually exclusive")
        for name in ("cwd", "root"):
            if options.get(name) is not None:
                _append_path_option(argv, "--" + name, _argument(options[name], label=name))
        if endpoint is not None:
            argv += ["--from", _text_arg(endpoint, label="from_")]
        _append_path_option(argv, "--src", _argument(path, label="src"))
        argv += ["--as-fd", "1"]
    for name, value in options.items():
        if name in {"as_new", "as_existing", "cwd", "root"}:
            continue
        if value is None or value is False:
            continue
        option = "--" + name.replace("_", "-")
        if name == "verbose":
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
                raise SyqInvocationError("verbose must be an integer from 0 to 255")
            argv += ["-v"] * value
            continue
        if name == "s3_header":
            for header in ([value] if isinstance(value, str) else value):
                _append_path_option(argv, option, _text_arg(header, label=name))
            continue
        if name in {"no_bootstrap", "no_compress", "no_tcp", "tcp_plain", "follow_src", "follow_dst",
                    "stats", "quiet", "progress", "no_progress", "dry_run", "only_new", "only_existing"}:
            if not isinstance(value, bool):
                raise SyqInvocationError(f"{name} must be a boolean")
            argv.append(option)
        else:
            _append_path_option(argv, option, _argument(value, label=name))
    _warn_unsupported_copy_options(only_existing=options.get("only_existing"),
                                   integrity_checking=options.get("integrity_checking"))
    return argv


def _signal_group(process: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin may report EPERM for a group containing only zombies.
        if process.poll() is None:
            raise
        process.wait()
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass


class _Process:
    def __init__(self, argv: list[Argument], *, writing: bool,
                 cwd: PathArgument | None, env: Mapping[str, str] | None,
                 timeout: float | None, dry_run: bool = False) -> None:
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                                    or not math.isfinite(timeout) or timeout < 0):
            raise SyqInvocationError("timeout must be a finite non-negative number or None")
        self.prepared = threading.Event()
        self.skipped = False
        self.transfer_ready = False
        self.dry_run = dry_run
        self.result: CpResult | None = None
        self.decoder = AutomationDecoder(dry_run=dry_run)
        self.results_error: Exception | None = None
        self.timeout = timeout
        self.expired = False
        self.cleanup_expired = False
        self.done = threading.Event()
        self.control = None
        self.stderr = bytearray()
        self._release_lock = threading.Lock()
        self._abort_lock = threading.Lock()
        self._released = False
        read_fd = write_fd = results_read = results_write = None
        try:
            from .client import _results_pipe
            results_read, results_write = _results_pipe()
            argv = [*argv, "--results-fd", str(results_write)]
            if writing:
                from .client import _results_pipe
                read_fd, write_fd = _results_pipe()
                argv = [*argv, "--stream-commit-fd", str(read_fd)]
            self.argv = tuple(argv)
            self.process = subprocess.Popen(
                argv, cwd=cwd, env=env, start_new_session=True,
                stdin=subprocess.PIPE if writing else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL if writing else subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(results_write,) if read_fd is None else (results_write, read_fd),
                bufsize=0,
            )
            self.results_pipe = os.fdopen(results_read, "rb")
            results_read = None
            if write_fd is not None:
                self.control = os.fdopen(write_fd, "wb", buffering=0)
                write_fd = None
        finally:
            for fd in (read_fd, write_fd, results_read, results_write):
                if fd is not None:
                    os.close(fd)
        self.payload = self.process.stdin if writing else self.process.stdout
        assert self.payload is not None and self.process.stderr is not None
        self.drain = threading.Thread(target=self._drain, daemon=True, name="syq-stream-stderr")
        self.drain.start()
        self.results_drain = threading.Thread(target=self._drain_results, daemon=True, name="syq-stream-results")
        self.results_drain.start()
        self.watchdog = None
        if timeout is not None:
            self.watchdog = threading.Thread(target=self._deadline, daemon=True, name="syq-stream-timeout")
            self.watchdog.start()

    def _drain(self) -> None:
        while chunk := self.process.stderr.read(8192):
            self.stderr.extend(chunk)
            del self.stderr[:-8192]

    def _drain_results(self) -> None:
        with self.results_pipe:
            for line in self.results_pipe:
                if self.results_error is None:
                    try:
                        record = json.loads(line)
                        if record["type"] == "run":
                            self.decoder.expected_dry_run = record.get("dry_run")
                        event = self.decoder.feed(line)
                        if record["type"] == "stream_ready":
                            self.transfer_ready = True
                            self.prepared.set()
                        elif record["type"] == "stream_result":
                            self.skipped = record["disposition"] == "skipped"
                        if isinstance(event, CpResult):
                            self.dry_run = event.dry_run
                            self.result = event
                    except Exception as error:
                        self.results_error = error
                        self.prepared.set()
        self.prepared.set()  # EOF also wakes a failed/skipped/preview open.

    def wait_prepared(self) -> None:
        self.prepared.wait()
        if self.results_error is not None:
            self.abort()
            raise self.results_error
        if not self.transfer_ready:
            self.finish()
            if not self.skipped and not self.dry_run:
                raise SyqProtocolError("stream ended without becoming ready")

    def _deadline(self) -> None:
        if not self.done.wait(self.timeout):
            self.expired = True
            # An exited coordinator cannot clean up descendants holding pipes.
            if self.process.poll() is not None:
                # Drained diagnostics do not imply payload EOF: read() may
                # still be blocked on a pipe held by a descendant. Only release
                # after payload completion may finish without killing the group.
                if (self._released and not self.drain.is_alive()
                        and not self.results_drain.is_alive()):
                    return
                self.cleanup_expired = True
                _signal_group(self.process, signal.SIGKILL)
                return
            # Let the coordinator close its helper sessions and discard staging.
            # Signalling the entire group here also kills local SSH helpers before
            # they can process Shutdown; the bounded fallback below kills leftovers.
            self.process.terminate()
            if not self.done.wait(6):
                self.cleanup_expired = True
                _signal_group(self.process, signal.SIGKILL)

    def _release(self) -> None:
        with self._release_lock:
            if self._released:
                return
            self._released = True
            # Completion includes EOF on both diagnostic and result pipes.
            # Keep the watchdog active until their owners actually close them.
            self.drain.join()
            self.results_drain.join()
            self.done.set()
            if self.watchdog is not None:
                self.watchdog.join()
            self.process.stderr.close()
            control, self.control = self.control, None
            if control is not None:
                control.close()
            self.payload.close()

    def finish(self) -> None:
        self.process.wait()
        self._release()
        if self.cleanup_expired or (self.expired and self.process.returncode != 0):
            raise subprocess.TimeoutExpired(self.argv, self.timeout, stderr=bytes(self.stderr))
        if self.process.returncode == 0:
            if self.results_error is not None:
                raise self.results_error
            self.decoder.finish(0)
            return
        if self.process.returncode:
            from .client import Result
            raise SyqProcessError(Result(self.argv, self.process.returncode, b"", bytes(self.stderr)))

    def abort(self) -> None:
        with self._abort_lock:
            if self.done.is_set():
                return
            # EOF on this channel cannot authorize publication.
            control, self.control = self.control, None
            if control is not None:
                control.close()
            # Let the coordinator close its helper sessions and discard staging.
            # Signalling the entire group here also kills local SSH helpers before
            # they can process Shutdown; the bounded fallback below kills leftovers.
            self.process.terminate()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                pass
            finally:
                _signal_group(self.process, signal.SIGKILL)
                self.process.wait()
                self._release()


class StreamWriter:
    """Sequential binary writer. close() ends input; commit() publishes it."""
    def __init__(self, process: _Process) -> None:
        self._process = process
        self.closed = False
        self._committed = False
        self._aborted = False

    @property
    def result(self) -> CpResult | None:
        """Terminal copy result, available after completion; None if interrupted."""
        return self._process.result

    @property
    def skipped(self) -> bool:
        return self._process.skipped

    @property
    def dry_run(self) -> bool:
        return self._process.dry_run

    @property
    def stderr(self) -> bytes:
        """The latest 8 KiB of diagnostics; complete after commit or reader close."""
        return bytes(self._process.stderr)

    def __del__(self) -> None:
        try:
            self.abort()
        except Exception:
            pass

    def _wait_prepared(self) -> None:
        try:
            self._process.wait_prepared()
        except BaseException:
            self.abort()
            raise

    def __enter__(self) -> StreamWriter:
        self._check_open()
        return self

    def __exit__(self, typ, value, traceback) -> None:
        if typ is None:
            if not self._aborted:
                self.commit()
        else:
            self.abort()

    def _check_open(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed stream")

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return not (self.dry_run or self.skipped)

    def seekable(self) -> bool:
        return False

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self._check_open()
        if self.skipped:
            raise ValueError("the stream destination was skipped")
        if self.dry_run:
            raise ValueError("a dry run does not accept payload bytes")
        remaining = memoryview(data).cast("B")
        total = len(remaining)
        try:
            while remaining:
                written = self._process.payload.write(remaining)
                if not written:
                    raise BrokenPipeError("stream writer made no progress")
                remaining = remaining[written:]
        except OSError:
            self.abort()
            if self._process.expired:
                raise subprocess.TimeoutExpired(self._process.argv, self._process.timeout,
                                                stderr=bytes(self._process.stderr)) from None
            from .client import Result
            raise SyqProcessError(Result(self._process.argv, self._process.process.returncode,
                                         b"", bytes(self._process.stderr))) from None
        return total

    def flush(self) -> None:
        self._check_open()  # Writes go directly to the transport's bounded pipe.

    def close(self) -> None:
        """End payload input, leaving publication to commit() or context exit."""
        if not self.closed:
            self.closed = True
            self._process.payload.close()

    def commit(self) -> None:
        """End input, authorize publication, and check transfer completion."""
        if self._committed:
            return
        if self._aborted:
            raise ValueError("cannot commit an aborted stream")
        try:
            self.close()
            if self.skipped or self.dry_run:
                self._process.finish()
                self._committed = True
                return
            assert self._process.control is not None
            if not self._process.expired and not self.dry_run:
                self._process.control.write(b"C")
            self._process.control.close()
            self._process.control = None
            self._process.finish()
            self._committed = True
        except OSError:
            self.abort()
            if self._process.expired:
                raise subprocess.TimeoutExpired(self._process.argv, self._process.timeout,
                                                stderr=bytes(self._process.stderr)) from None
            from .client import Result
            raise SyqProcessError(Result(self._process.argv, self._process.process.returncode,
                                         b"", bytes(self._process.stderr))) from None
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        self.closed = True
        if not self._committed:
            self._aborted = True
            if not self._process.done.is_set():
                self._process.abort()


class StreamReader:
    """Sequential binary reader. close() drains and checks; abort() cancels."""
    def __init__(self, process: _Process) -> None:
        self._process = process
        self.closed = False
        self._ended = False

    @property
    def result(self) -> CpResult | None:
        """Terminal copy result, available after completion; None if interrupted."""
        return self._process.result

    @property
    def skipped(self) -> bool:
        return self._process.skipped

    @property
    def dry_run(self) -> bool:
        return self._process.dry_run

    @property
    def stderr(self) -> bytes:
        """The latest 8 KiB of diagnostics; complete after commit or reader close."""
        return bytes(self._process.stderr)

    def __del__(self) -> None:
        try:
            self.abort()
        except Exception:
            pass

    def __enter__(self) -> StreamReader:
        if self.closed:
            raise ValueError("I/O operation on closed stream")
        return self

    def __exit__(self, typ, value, traceback) -> None:
        if typ is None:
            self.close()
        else:
            self.abort()

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def flush(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed stream")

    def read(self, size: int | None = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed stream")
        if self._ended:
            return b""
        data = self._process.payload.read(size)
        if size is None or size < 0 or (not data and size != 0):
            self._ended = True
            self._process.finish()
        return data

    def readinto(self, buffer) -> int:
        view = memoryview(buffer).cast("B")
        if view.readonly:
            raise TypeError("readinto() requires a writable buffer")
        data = self.read(len(view))
        view[:len(data)] = data
        return len(data)

    def close(self) -> None:
        if self.closed:
            return
        try:
            while self.read(65536):
                pass
            self.closed = True
        except BaseException:
            if not self._process.done.is_set():
                self._process.abort()
            self.closed = True
            raise

    def abort(self) -> None:
        self.closed = True
        if not self._process.done.is_set():
            self._process.abort()


async def _call(stream, method, *args):
    try:
        return await asyncio.to_thread(method, *args)
    except BaseException:
        # Cancellation must retire the process, releasing any blocking worker.
        await asyncio.shield(asyncio.to_thread(stream.abort))
        raise


class _AsyncStream:
    def __init__(self, factory: Callable[[], Awaitable[StreamReader | StreamWriter]]) -> None:
        self._factory = factory
        self._stream = None
        self._entered = False

    @property
    def result(self) -> CpResult | None:
        return self._active().result

    @property
    def skipped(self) -> bool:
        return self._active().skipped

    @property
    def dry_run(self) -> bool:
        return self._active().dry_run

    @property
    def stderr(self) -> bytes:
        """The latest 8 KiB of diagnostics from the active or completed stream."""
        return self._active().stderr

    async def __aenter__(self):
        if self._entered:
            raise ValueError("stream context cannot be reused")
        self._entered = True
        self._stream = await self._factory()
        return self

    def _active(self):
        if self._stream is None:
            raise ValueError("use the stream inside async with")
        return self._stream

    async def __aexit__(self, typ, value, traceback) -> None:
        if typ is None:
            await self.close()
        else:
            await self.abort()

    async def close(self) -> None:
        stream = self._active()
        await _call(stream, stream.close)

    async def abort(self) -> None:
        if self._stream is not None:
            await asyncio.to_thread(self._stream.abort)


class AsyncStreamWriter(_AsyncStream):
    async def __aexit__(self, typ, value, traceback) -> None:
        stream = self._active()
        await _call(stream, stream.__exit__, typ, value, traceback)

    async def commit(self) -> None:
        stream = self._active()
        await _call(stream, stream.commit)

    async def write(self, data: bytes | bytearray | memoryview) -> int:
        stream = self._active()
        return await _call(stream, stream.write, data)


class AsyncStreamReader(_AsyncStream):
    async def read(self, size: int | None = -1) -> bytes:
        stream = self._active()
        return await _call(stream, stream.read, size)
