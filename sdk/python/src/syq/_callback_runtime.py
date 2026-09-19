"""Bounded callbacks admitted by a single native mapping session."""
from __future__ import annotations

import asyncio
import inspect
import io
import os
import signal
import socket
import subprocess
import threading

from ._callback_io import AsyncPayload, Reader, TransferState, Writer, _TransferError
from ._stream_channel import VERSION, receive, send
from ._stream_endpoints import StreamSource, StreamDestination
from .errors import SyqInvocationError, SyqProtocolError
from .models import MappingEntry


def _async(function) -> bool:
    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(getattr(function, "__call__", None))


class Callbacks:
    def __init__(self, entries: dict[int, MappingEntry], concurrency: int, *, loop=None) -> None:
        if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= 256:
            raise SyqInvocationError("stream_concurrency must be an integer from 1 to 256")
        self.entries = entries
        self.concurrency = concurrency
        self.loop = loop
        if loop is None:
            for entry in entries.values():
                for endpoint in (entry.src, entry.dst):
                    function = endpoint.produce if isinstance(endpoint, StreamSource) else endpoint.consume if isinstance(endpoint, StreamDestination) else None
                    if function is not None and _async(function):
                        raise SyqInvocationError("async stream callbacks require AsyncClient")
        self.channel, self.child = socket.socketpair()
        self._lock = threading.Lock()
        self._states: dict[int, TransferState] = {}
        self._started: set[tuple[int, str]] = set()
        self._threads: list[threading.Thread] = []
        self._async_tasks: set = set()
        self._process: subprocess.Popen | None = None
        self._error: BaseException | None = None
        self._cancelled = threading.Event()
        self._reader: threading.Thread | None = None

    def attach(self, process: subprocess.Popen) -> None:
        self.child.close()
        with self._lock:
            self._process = process
        self._reader = threading.Thread(target=self._serve, name="syq-mapping-control", daemon=True)
        self._reader.start()
        if self._cancelled.is_set():
            self.request_abort()

    def request_abort(self) -> None:
        self._cancelled.set()
        with self._lock:
            process = self._process
            tasks = tuple(self._async_tasks)
        for task in tasks:
            task.cancel()
        if process is not None and process.poll() is None:
            try:
                process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass

    def _fail(self, error: BaseException) -> None:
        with self._lock:
            if self._error is None:
                self._error = error
        self.request_abort()

    def _serve(self) -> None:
        try:
            hello, fds = receive(self.channel)
            try:
                if hello != {"type": "hello", "version": VERSION} or fds:
                    raise SyqProtocolError("unsupported stream mapping handshake")
            finally:
                for fd in fds:
                    os.close(fd)
            send(self.channel, {"version": VERSION})
            while True:
                record, fds = receive(self.channel)
                try:
                    kind = record.get("type")
                    if kind == "end" and not fds:
                        return
                    index = record.get("entry")
                    if isinstance(index, bool) or not isinstance(index, int) or index not in self.entries:
                        raise SyqProtocolError("unknown stream mapping entry")
                    if kind == "transferred" and not fds:
                        error = record.get("error")
                        if error is not None and not isinstance(error, str):
                            raise SyqProtocolError("invalid stream transfer error")
                        if index not in self._states or self._states[index].done.is_set():
                            raise SyqProtocolError("unexpected stream completion")
                        self._states[index].settle(error)
                        continue
                    if kind != "start" or len(fds) != 2:
                        raise SyqProtocolError("invalid stream mapping admission")
                    direction = record.get("direction")
                    entry = self.entries[index]
                    endpoint = entry.src if direction == "produce" else entry.dst if direction == "consume" else None
                    if not isinstance(endpoint, StreamSource if direction == "produce" else StreamDestination):
                        raise SyqProtocolError("callback direction does not match its mapping")
                    identity = (index, direction)
                    if identity in self._started:
                        raise SyqProtocolError("stream callback was invoked twice")
                    self._started.add(identity)
                    state = self._states.setdefault(index, TransferState())
                    if self._cancelled.is_set():
                        continue
                    self._threads = [thread for thread in self._threads if thread.is_alive()]
                    thread = threading.Thread(target=self._invoke, args=(endpoint, state, *fds), name=f"syq-stream-{index}-{direction}", daemon=True)
                    self._threads.append(thread)
                    thread.start()
                    fds = []  # Ownership belongs to the callback thread now.
                finally:
                    for fd in fds:
                        os.close(fd)
        except BaseException as error:
            if not self._cancelled.is_set():
                self._fail(error)
        finally:
            for state in self._states.values():
                state.settle("stream mapping session ended before transfer completion")

    def wait_async(self, coroutine):
        task = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        with self._lock:
            self._async_tasks.add(task)
        try:
            if self._cancelled.is_set():
                task.cancel()
            return task.result()
        finally:
            with self._lock:
                self._async_tasks.discard(task)

    def _invoke(self, endpoint, state: TransferState, payload_fd: int, commit_fd: int) -> None:
        writer = isinstance(endpoint, StreamSource)
        payload = io.FileIO(payload_fd, "wb" if writer else "rb", closefd=True)
        stream = Writer(payload, state) if writer else Reader(payload, state)
        try:
            function = endpoint.produce if writer else endpoint.consume
            if _async(function):
                async def invoke():
                    return await function(AsyncPayload(stream))
                self.wait_async(invoke())
            else:
                result = function(stream)
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result.close()
                    raise SyqInvocationError("declare an async callback with async def and use AsyncClient")
            if writer:
                stream.close()
            else:
                stream.finish()
            if not self._cancelled.is_set():
                os.write(commit_fd, b"C")
        except _TransferError:
            pass  # The native per-entry result reports this transfer failure.
        except BaseException as error:
            if not self._cancelled.is_set():
                self._fail(error)
        finally:
            payload.close()
            os.close(commit_fd)

    def raise_error(self) -> None:
        if self._error is not None:
            raise self._error

    def close(self, *, abort: bool) -> None:
        if abort:
            self.request_abort()
            process = self._process
            if process is not None:
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    from .client import _kill_process_group
                    _kill_process_group(process)
                    process.wait()
        self.child.close()
        if not abort and self._reader is not None:
            self._reader.join()
        try:
            self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self._reader is not None:
            self._reader.join()
        self.channel.close()
        # Arbitrary Python computation cannot be forcibly cancelled. Payload
        # I/O has ended; callbacks that continue computing must cooperate.
