"""Keep an owned payload descriptor alive until its active I/O has returned."""
import io
import threading


class OwnedPayload(io.RawIOBase):
    def __init__(self, file):
        self._file = file
        self._lock = threading.RLock()

    def readable(self):
        return self._file.readable()

    def writable(self):
        return self._file.writable()

    def fileno(self):
        return self._file.fileno()

    def read(self, size=-1):
        with self._lock:
            return self._file.read(size)

    def readinto(self, buffer):
        with self._lock:
            return self._file.readinto(buffer)

    def write(self, data):
        with self._lock:
            return self._file.write(data)

    def flush(self):
        with self._lock:
            if not self._file.closed:
                self._file.flush()

    def close(self):
        # Cancelling asyncio.to_thread does not stop the underlying syscall.
        # Teardown first stops the native peer, then waits here for I/O to exit;
        # otherwise read-all/write loops can use a closed and recycled FD.
        with self._lock:
            try:
                super().close()
            finally:
                self._file.close()
