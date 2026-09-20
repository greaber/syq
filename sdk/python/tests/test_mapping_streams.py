from __future__ import annotations

import socket
import sys
import unittest

import syq
from syq._stream_channel import receive, send
from syq.models import _mapping_json


class MappingStreamTypes(unittest.TestCase):
    def test_callbacks_are_live_endpoints_with_explicit_metadata(self):
        source = syq.StreamSource(lambda out: out.write(b"archive"), size=7)
        entry = syq.MappingEntry(source, "part.tar", metadata=syq.DestinationMetadata(mode=0o640))
        self.assertIs(entry.src, source)
        self.assertEqual(entry.dst, syq.RelativePath("part.tar"))
        with self.assertRaisesRegex(ValueError, "live SDK copy"):
            _mapping_json(entry)
        consumer = syq.StreamDestination(lambda reader: reader.read())
        with self.assertRaisesRegex(ValueError, "named destination"):
            syq.MappingEntry("part.tar", consumer, metadata=syq.DestinationMetadata(mode=0o640))
        for kind in ("dir", "symlink", "special"):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "regular-file bytes"):
                syq.MappingEntry(source, "entry", kind=kind)
        for size in (-1, True, 2**64, 0.1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                syq.StreamSource(lambda out: None, size=size)

    def test_control_frame_keeps_its_descriptor_separate_from_following_frame(self):
        from array import array
        import os
        import struct
        import tempfile
        with tempfile.TemporaryFile() as payload:
            payload.write(b"payload")
            payload.seek(0)
            left, right = socket.socketpair()
            with left, right:
                left.sendmsg([b"S"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [payload.fileno()]))])
                left.sendall(struct.pack("!I", 2) + b"{}")
                send(left, {"next": True})
                record, descriptors = receive(right)
                self.assertEqual(record, {})
                self.assertEqual(len(descriptors), 1)
                with os.fdopen(descriptors[0], "rb") as copied:
                    self.assertFalse(os.get_inheritable(copied.fileno()))
                    self.assertEqual(copied.read(), b"payload")
                self.assertEqual(receive(right), ({"next": True}, []))


class MappingStreamCopies(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile
        from pathlib import Path
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = Path(os.environ.get("SYQ_CANDIDATE_EXECUTABLE", Path(__file__).resolve().parents[3] / "target/debug/syq"))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("SYQ_")}
        self.env["HOME"] = str(self.root)
        self.client = syq.Client(executable=self.binary, env=self.env, timeout=10)

    def test_upload_download_mixed_paths_metadata_and_outcomes(self):
        import hashlib
        import io
        source = self.root / "source"
        source.mkdir()
        ordinary = source / "ordinary"
        ordinary.write_bytes(b"ordinary file")
        destination = self.root / "destination"
        events = []
        entries = [
            syq.MappingEntry("ordinary", "ordinary"),
            syq.MappingEntry(syq.StreamSource(lambda out: out.write(b"archive"), size=7), "nested/part.tar",
                metadata=syq.DestinationMetadata(mode=0o640, mtime=123, mtime_nsec=456),
                expected_hash=syq.Hash("sha256", hashlib.sha256(b"archive").hexdigest())),
        ]
        result = self.client.cp(mapping=entries, cwd=source, into_new=destination, on_event=events.append)
        self.assertEqual(result.bytes_transferred, 20)
        target = destination / "nested/part.tar"
        self.assertEqual(target.read_bytes(), b"archive")
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(target.stat().st_mtime_ns, 123_000_000_456)
        streams = [e for e in events if isinstance(e, syq.MappingStreamResult)]
        self.assertEqual([(e.entry, e.disposition) for e in streams], [(1, "succeeded")])
        self.assertIsNone(streams[0].source)
        self.assertEqual(streams[0].destination.raw, b"nested/part.tar")
        result = self.client.cp(mapping=entries, cwd=source, into=destination)
        self.assertEqual(result.files_unchanged, 1)
        self.assertEqual(result.files_transferred, 1)  # No implicit callback replay avoidance.
        data = []
        def consume(source):
            with io.TextIOWrapper(source, encoding="utf-8") as text:
                data.append(text.read())
        self.client.cp(mapping=[syq.MappingEntry("nested/part.tar", syq.StreamDestination(consume))], cwd=destination)
        self.assertEqual(data, ["archive"])

    def test_skip_preview_and_invalid_later_entry_do_not_start_callbacks(self):
        calls = []
        produce = syq.StreamSource(lambda out: calls.append(True))
        target = self.root / "existing"
        target.write_bytes(b"old")
        entries = [syq.MappingEntry(produce, "existing")]
        result = self.client.cp(mapping=entries, into=self.root, only_new=True)
        self.assertEqual(result.files_excluded, 1)
        self.client.cp(mapping=entries, into=self.root, dry_run=True)
        with self.assertRaises(syq.SyqOperationError):
            self.client.cp(mapping=[syq.MappingEntry(produce, "new"), syq.MappingEntry(produce, "new/child")], into=self.root)
        self.assertEqual(calls, [])
        self.assertFalse((self.root / "new").exists())
        self.assertEqual(target.read_bytes(), b"old")

    def test_wrapper_close_during_exception_never_publishes(self):
        import io
        for wrapper in (io.BufferedWriter, lambda out: io.TextIOWrapper(out, encoding="utf-8")):
            target = self.root / "existing"
            target.write_bytes(b"old")
            def produce(out):
                with wrapper(out) as buffered:
                    buffered.write("partial" if isinstance(buffered, io.TextIOWrapper) else b"partial")
                    raise ValueError("producer failed")
            with self.subTest(wrapper=wrapper), self.assertRaisesRegex(ValueError, "producer failed"):
                self.client.cp(mapping=[syq.MappingEntry(syq.StreamSource(produce), "existing")], into=self.root)
            self.assertEqual(target.read_bytes(), b"old")
            self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["existing"])

    def test_promised_size_and_hash_failures_preserve_destination_and_have_identity(self):
        target = self.root / "existing"
        target.write_bytes(b"old")
        for size, expected_hash in ((3, None), (5, None), (4, syq.Hash("sha256", "0" * 64))):
            events = []
            result = self.client.cp(mapping=[syq.MappingEntry(syq.StreamSource(lambda out: out.write(b"data"), size=size), "existing", expected_hash=expected_hash)], into=self.root, on_event=events.append, check=False)
            self.assertEqual(result.exit_code, 23)
            failure, = [e for e in events if isinstance(e, syq.MappingStreamResult)]
            self.assertEqual((failure.entry, failure.disposition), (0, "failed"))
            self.assertTrue(failure.message)
            self.assertEqual(target.read_bytes(), b"old")

    def test_consumer_eof_validates_transfer_and_normal_early_return_drains(self):
        target = self.root / "source"
        target.write_bytes(b"x" * 1024 * 1024)
        returned = []
        def consume(source):
            returned.append(source.read())
        result = self.client.cp(mapping=[syq.MappingEntry("source", syq.StreamDestination(consume), expected_hash=syq.Hash("sha256", "0" * 64))], cwd=self.root, check=False)
        self.assertEqual(result.exit_code, 23)
        self.assertEqual(returned, [])
        def prefix(source):
            self.assertEqual(source.read(1), b"x")
            source.close()
        result = self.client.cp(mapping=[syq.MappingEntry("source", syq.StreamDestination(prefix))], cwd=self.root)
        self.assertEqual(result.bytes_transferred, 1024 * 1024)

    @unittest.skipUnless(sys.platform.startswith("linux"), "counts native threads through /proc")
    def test_shared_worker_limit_bounds_native_threads(self):
        import threading
        import time
        from functools import partial
        from pathlib import Path
        from unittest.mock import patch
        from syq._callback_runtime import Callbacks

        barrier = threading.Barrier(16)
        release = threading.Event()
        process_ids = []
        attach = Callbacks.attach
        def attached(callbacks, process):
            process_ids.append(process.pid)
            attach(callbacks, process)
        def produce(index, output):
            barrier.wait(timeout=5)
            if index == 0:
                try:
                    # Keep all entries open long enough for workers waiting on
                    # the shared ceiling to appear if they own native threads.
                    deadline = time.monotonic() + 0.15
                    peak = 0
                    while time.monotonic() < deadline:
                        names = []
                        for task in Path(f"/proc/{process_ids[0]}/task").iterdir():
                            try:
                                names.append((task / "comm").read_text().strip())
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                        active = sum(name.startswith("stream-") for name in names)
                        peak = max(peak, active)
                        self.assertLessEqual(active, 16, "waiting entries created extra worker threads")
                        time.sleep(0.005)
                    self.assertGreater(peak, 0)
                finally:
                    release.set()
            else:
                self.assertTrue(release.wait(timeout=5))
            output.write(bytes([index]) * 65536)
        entries = [syq.MappingEntry(syq.StreamSource(partial(produce, i)), str(i)) for i in range(16)]
        with patch.object(Callbacks, "attach", attached):
            result = self.client.cp(mapping=entries, into=self.root, stream_concurrency=16,
                                    performance_tuning="workers=16")
        self.assertEqual(result.files_transferred, 16)
        for i in range(16):
            self.assertEqual((self.root / str(i)).read_bytes(), bytes([i]) * 65536)

    def test_concurrency_is_bounded_and_cancelled_full_producer_does_not_hang(self):
        import threading
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        active = maximum = 0
        calls = []
        def produce(out):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(active, maximum)
            try:
                barrier.wait(timeout=5)
                out.write(b"x" * 1024 * 1024)
                calls.append(True)
            finally:
                with lock:
                    active -= 1
        entries = [syq.MappingEntry(syq.StreamSource(produce), str(i)) for i in range(8)]
        self.client.cp(mapping=entries, into=self.root, stream_concurrency=2, performance_tuning="workers=1")
        self.assertEqual((maximum, len(calls)), (2, 8))
        def infinite(out):
            while True:
                out.write(b"x" * 65536)
        def fail(source):
            source.read(1)
            raise RuntimeError("consumer failed")
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            self.client.cp(mapping=[syq.MappingEntry(syq.StreamSource(infinite), syq.StreamDestination(fail))])

    def test_s3_callbacks_publish_complete_objects_and_validate_downloads(self):
        import subprocess
        import sys
        from pathlib import Path
        fixture = Path(__file__).resolve().parents[3] / "tests/object-storage/stream-faults.py"
        result = subprocess.run([sys.executable, fixture, self.binary, "mapping-callbacks"], capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())

    def test_async_callbacks_and_cancellation(self):
        import asyncio
        async def test():
            client = syq.AsyncClient(executable=self.binary, env=self.env, timeout=10)
            got = []
            async def producer(out):
                await out.write(b"async")
            async def consumer(source):
                got.append(await source.read())
            async def entries():
                yield syq.MappingEntry(syq.StreamSource(producer), syq.StreamDestination(consumer))
            result = await client.cp(mapping=entries())
            self.assertEqual((got, result.bytes_transferred), ([b"async"], 5))
            started = asyncio.Event()
            async def blocked(out):
                started.set()
                while True:
                    await out.write(b"x" * 65536)
            async def stalled(source):
                await asyncio.Event().wait()
            task = asyncio.create_task(client.cp(mapping=[syq.MappingEntry(syq.StreamSource(blocked), syq.StreamDestination(stalled))]))
            await asyncio.wait_for(started.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 8)
        import asyncio
        asyncio.run(test())
