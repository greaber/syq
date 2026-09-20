"""File objects whose lifetime is separate from a callback's successful return."""
from __future__ import annotations

import asyncio
import io
import threading

from .errors import SyqError


class _TransferError(SyqError):
    """An entry failed in the native executor, rather than in application code."""


class TransferState:
    def __init__(self) -> None:
        self.done = threading.Event()
        self.error: str | None = None

    def settle(self, error: str | None) -> None:
        if not self.done.is_set():
            self.error = error
            self.done.set()

    def wait(self) -> None:
        self.done.wait()
        if self.error is not None:
            raise _TransferError(self.error)


class Writer(io.RawIOBase):
    def __init__(self, file: io.FileIO, state: TransferState) -> None:
        self.file, self.state = file, state

    def writable(self) -> bool:
        return not self.closed

    def fileno(self) -> int:
        self._checkClosed()
        return self.file.fileno()

    def write(self, data) -> int:
        self._checkClosed()
        view = memoryview(data).cast("B")
        size = len(view)
        try:
            while view:
                count = self.file.write(view)
                if not count:
                    raise OSError("stream writer made no progress")
                view = view[count:]
        except BrokenPipeError:
            self.state.wait()
            raise
        return size

    def close(self) -> None:
        if not self.closed:
            try:
                super().close()
            finally:
                self.file.close()


class Reader(io.RawIOBase):
    def __init__(self, file: io.FileIO, state: TransferState) -> None:
        self.file, self.state = file, state

    def readable(self) -> bool:
        return not self.closed

    def fileno(self) -> int:
        self._checkClosed()
        return self.file.fileno()

    def read(self, size: int | None = -1) -> bytes:
        self._checkClosed()
        data = self.file.read(-1 if size is None else size)
        if size is None or size < 0 or (size != 0 and not data):
            self.state.wait()
        return data

    def readinto(self, buffer) -> int:
        self._checkClosed()
        count = self.file.readinto(buffer)
        if count == 0 and len(memoryview(buffer)):
            self.state.wait()
        return count

    def finish(self) -> None:
        # A wrapper may already have logically closed this reader. The owner
        # drains only after normal callback return, never while unwinding it.
        while self.file.read(1024 * 1024):
            pass
        self.state.wait()

    def dispose(self) -> None:
        super().close()
        self.file.close()


class AsyncPayload:
    """Async callback view; synchronous archive callbacks use the raw view."""

    def __init__(self, stream: Reader | Writer) -> None:
        self.stream = stream

    @property
    def closed(self) -> bool:
        return self.stream.closed

    async def read(self, size: int | None = -1) -> bytes:
        return await asyncio.to_thread(self.stream.read, size)

    async def readinto(self, buffer) -> int:
        return await asyncio.to_thread(self.stream.readinto, buffer)

    async def write(self, data) -> int:
        return await asyncio.to_thread(self.stream.write, data)

    async def flush(self) -> None:
        await asyncio.to_thread(self.stream.flush)

    async def close(self) -> None:
        await asyncio.to_thread(self.stream.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, typ, value, traceback):
        await self.close()
