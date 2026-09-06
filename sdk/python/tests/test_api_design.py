from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import os
import subprocess
import tempfile
import unittest
import weakref
from pathlib import Path

import syq

from test_native import FAKE_NATIVE


class ErrorAndTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.root / "syq"
        self.executable.write_text(FAKE_NATIVE)
        self.executable.chmod(0o755)
        self.env = {**os.environ, "SYQ_FAKE_PAUSE": "0.03"}

    def call(self, client, command, **options):
        if command == "map":
            with client.map("source", **options) as mapping:
                return list(mapping)
        if command == "run":
            return client.run(["map", "source"], **options)
        if command == "cp":
            return client.cp("source", into="destination", **options)
        return client.rm("source", **options)

    def test_omitted_timeout_inherits_none_disables_and_number_overrides(self):
        client = syq.Client(executable=self.executable, env=self.env, timeout=0)
        for command in ("cp", "rm", "map", "run"):
            with self.subTest(command=command):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.call(client, command)
                def forward(*, timeout: syq.Timeout = syq.CLIENT_DEFAULT):
                    return self.call(client, command, timeout=timeout)
                with self.assertRaises(subprocess.TimeoutExpired):
                    forward()
                forward(timeout=None)
                forward(timeout=5)
                self.assertEqual(client.timeout, 0)

    def test_common_error_base_preserves_specific_error_types(self):
        for error_type in (syq.SyqInstallError, syq.SyqInvocationError,
                           syq.SyqProcessError, syq.SyqOutputError,
                           syq.SyqProtocolError, syq.SyqOperationError):
            self.assertTrue(issubclass(error_type, syq.SyqError))
        client = syq.Client(executable=self.executable)
        with self.assertRaises(syq.SyqError) as caught:
            client.cp("source", into="a", as_="b")
        self.assertIsInstance(caught.exception, syq.SyqInvocationError)
        client.env = {**os.environ, "SYQ_FAKE_STATUS": "partial"}
        with self.assertRaises(syq.SyqError) as caught:
            client.cp("source", into="a")
        self.assertIsInstance(caught.exception, syq.SyqOperationError)
        self.assertIs(caught.exception.result.status, syq.OperationStatus.PARTIAL)

    def test_callback_exception_is_not_wrapped(self):
        failure = LookupError("application error")
        def callback(event):
            raise failure
        client = syq.Client(executable=self.executable)
        with self.assertRaises(LookupError) as caught:
            client.cp("source", into="destination", on_event=callback)
        self.assertIs(caught.exception, failure)
        self.assertNotIsInstance(caught.exception, syq.SyqError)

    def test_grouped_metadata_keeps_saved_wire_records_unchanged(self):
        client = syq.Client(executable=self.executable,
                            env={**os.environ, "SYQ_FAKE_SHAPE": "attested"})
        events = []
        output = io.BytesIO()
        result = client.cp("source", into="destination", results=output,
                           on_event=events.append)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), len(events))
        for event, record in zip(events, records):
            self.assertEqual(dataclasses.asdict(event.protocol),
                             {key: record[key] for key in ("schema", "schema_version", "seq", "type")})
            self.assertNotIn("protocol", record)
            self.assertFalse(hasattr(event, "seq"))
        self.assertIs(result.receipt.status, syq.ReceiptStatus.CLEAN)
        self.assertEqual(result.receipt.records, records[-1]["receipt_records"])
        self.assertEqual(result.receipt.provenance, records[-1]["provenance"])
        self.assertFalse(hasattr(result, "receipt_status"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.protocol.seq = 0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.receipt.records = 0
        final = next(event for event in events if isinstance(event, syq.FinalStateEvent))
        # Filesystem metadata and protocol metadata remain distinct.
        self.assertIsInstance(final.protocol, syq.ProtocolMetadata)
        self.assertTrue(final.metadata is None or isinstance(final.metadata, syq.ObjectMetadata))


class AsyncTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_unstarted_stream_has_no_self_reference_cycle(self):
        stream = syq.AsyncClient().map("source")
        reference = weakref.ref(stream)
        del stream
        self.assertIsNone(reference())

    async def test_timeout_overrides_for_all_async_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "syq"
            executable.write_text(FAKE_NATIVE)
            executable.chmod(0o755)
            client = syq.AsyncClient(executable=executable, timeout=0,
                                    env={**os.environ, "SYQ_FAKE_PAUSE": "0.03"})
            async def call(command, **options):
                if command == "map":
                    async with client.map("source", **options) as mapping:
                        return [entry async for entry in mapping]
                if command == "run":
                    return await client.run(["map", "source"], **options)
                if command == "cp":
                    return await client.cp("source", into="destination", **options)
                return await client.rm("source", **options)
            for command in ("cp", "rm", "map", "run"):
                with self.subTest(command=command):
                    with self.assertRaises(asyncio.TimeoutError):
                        await call(command)
                    async def forward(*, timeout: syq.Timeout = syq.CLIENT_DEFAULT):
                        return await call(command, timeout=timeout)
                    with self.assertRaises(asyncio.TimeoutError):
                        await forward()
                    await forward(timeout=None)
                    await forward(timeout=5)
                    self.assertEqual(client.timeout, 0)


EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")


@unittest.skipUnless(EXECUTABLE, "candidate binary required")
class MappingContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "a").write_bytes(b"correct source")
        (self.source / "b").write_bytes(b"omit this")
        self.other = self.root / "other"
        self.other.mkdir()
        (self.other / "a").write_bytes(b"wrong source")
        self.producer = syq.Client(executable=EXECUTABLE, process_cwd=self.root)
        self.consumer = syq.Client(executable=EXECUTABLE, process_cwd=self.other)

    def test_stream_transform_chain_preserves_context_and_filters(self):
        calls = []
        def select(entry):
            calls.append(entry)
            return entry if entry.src.text == "a" else None
        with self.producer.map(srcs_in="source") as mapping:
            transformed = mapping.transform(select).transform(
                lambda entry: dataclasses.replace(entry, dst=syq.RelativePath("renamed")))
            self.assertEqual(calls, [])
            self.consumer.cp(mapping=transformed, into="destination")
        self.assertEqual((self.other / "destination/renamed").read_bytes(), b"correct source")
        self.assertEqual(len(calls), 2)
        self.assertFalse((self.other / "destination/b").exists())
        with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
            self.consumer.cp(mapping=transformed, into="repeat")
        self.assertFalse((self.other / "repeat").exists())

    def test_direct_mapping_and_custom_entries_capture_source_base(self):
        with self.producer.map(srcs_in="source") as mapping:
            self.consumer.cp(mapping=mapping, into="direct")
        entries = syq.Mapping([syq.MappingEntry("a", "copied")], cwd=self.source)
        self.consumer.cp(mapping=entries, into="custom")
        self.assertEqual((self.other / "direct/a").read_bytes(), b"correct source")
        self.assertEqual((self.other / "custom/copied").read_bytes(), b"correct source")
        transformed = entries.transform(lambda entry: entry)
        self.consumer.cp(mapping=transformed, into="repeat-one")
        self.consumer.cp(mapping=transformed, into="repeat-two")
        self.assertEqual((self.other / "repeat-two/copied").read_bytes(), b"correct source")

    def test_explicit_source_overrides_are_rejected_before_copy(self):
        with self.producer.map(srcs_in="source") as mapping:
            for override in ({"cwd": mapping.cwd}, {"root": self.other}, {"from_": "server"}):
                with self.subTest(override=override), self.assertRaises(syq.SyqInvocationError):
                    self.consumer.cp(mapping=mapping, into="destination", **override)
        self.assertFalse((self.other / "destination").exists())

    def test_follow_policy_and_unresolved_components_survive_transformation(self):
        (self.source / "nested").mkdir()
        (self.root / "alias").symlink_to(self.source / "nested", target_is_directory=True)
        with self.producer.map(srcs_in="alias/..", follow_src=True) as mapping:
            transformed = mapping.transform(lambda entry: entry)
            self.assertIn("alias/..", str(transformed.cwd))
            self.assertTrue(transformed.follow_src)
            self.consumer.cp(mapping=transformed, into="destination")
        self.assertEqual((self.other / "destination/a").read_bytes(), b"correct source")

    def test_root_context_remains_confined_during_copy(self):
        with self.producer.map(srcs_in="source", root=self.root) as mapping:
            transformed = mapping.transform(lambda entry: entry)
            self.assertEqual(transformed.root, self.source)
            self.consumer.cp(mapping=transformed, into="destination")
        self.assertEqual((self.other / "destination/a").read_bytes(), b"correct source")
        # A transformed source symlink cannot escape the carried root.
        (self.source / "escape").symlink_to(self.other / "a")
        with self.producer.map(src="a", root=self.source) as mapping:
            transformed = mapping.transform(lambda entry: dataclasses.replace(entry, src=syq.RelativePath("escape")))
            with self.assertRaises(syq.SyqError):
                self.consumer.cp(mapping=transformed, into="escaped", follow_src=True)
        self.assertFalse((self.other / "escaped/a").exists())

    def test_closed_and_exhausted_streams_cannot_be_copied(self):
        for consume in (False, True):
            with self.producer.map(srcs_in="source") as mapping:
                transformed = mapping.transform(lambda entry: entry)
                if consume:
                    list(mapping)
            with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
                self.consumer.cp(mapping=transformed, into="destination")
        self.assertFalse((self.other / "destination").exists())

    def test_failed_transform_or_producer_never_starts_copy(self):
        def fail(entry):
            if entry.src.text == "b":
                raise LookupError("transform failed")
            return entry
        with self.producer.map(srcs_in="source") as mapping:
            with self.assertRaisesRegex(LookupError, "transform failed"):
                self.consumer.cp(mapping=mapping.transform(fail), into="destination")
        self.assertFalse((self.other / "destination").exists())
        # The committed source fixtures already exercise protocol truncation;
        # here use an actual producer failure after selecting a valid path.
        with self.producer.map(src=["source/a", "missing"]) as mapping:
            with self.assertRaises(syq.SyqError):
                self.consumer.cp(mapping=mapping.transform(lambda entry: entry), into="destination")
        self.assertFalse((self.other / "destination").exists())


@unittest.skipUnless(EXECUTABLE, "candidate binary required")
class AsyncMappingContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_transform_and_sync_mapping_cross_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/a").write_bytes(b"data")
            (root / "other").mkdir()
            producer = syq.AsyncClient(executable=EXECUTABLE, process_cwd=root)
            consumer = syq.AsyncClient(executable=EXECUTABLE, process_cwd=root / "other")
            async def rename(entry):
                await asyncio.sleep(0)
                return dataclasses.replace(entry, dst=syq.RelativePath("renamed"))
            async with producer.map(srcs_in="source", root=root) as mapping:
                transformed = mapping.transform(rename).transform(lambda entry: entry)
                self.assertEqual(transformed.root, root / "source")
                await consumer.cp(mapping=transformed, into="destination")
            self.assertEqual((root / "other/destination/renamed").read_bytes(), b"data")
            with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
                await consumer.cp(mapping=transformed, into="repeat")
            self.assertFalse((root / "other/repeat").exists())
            mapping = syq.Mapping([syq.MappingEntry("a", "a")], cwd=root / "source")
            await consumer.cp(mapping=mapping, into="sync-input")
            self.assertEqual((root / "other/sync-input/a").read_bytes(), b"data")

    async def test_lazy_map_snapshots_producer_directory_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "second"):
                (root / name).mkdir()
                (root / name / "a").write_text(name)
            env = {**os.environ, "HOME": str(root / "first")}
            client = syq.AsyncClient(executable=EXECUTABLE, process_cwd=root / "first", env=env)
            relative = client.map("a")
            home = client.map(srcs_in="~/")
            client.process_cwd = root / "second"
            env["HOME"] = str(root / "second")
            client.timeout = 0
            async with relative:
                await client.cp(mapping=relative, into=root / "relative", timeout=None)
            async with home:
                await client.cp(mapping=home, into=root / "home", timeout=None)
            self.assertEqual((root / "relative/a").read_text(), "first")
            self.assertEqual((root / "home/a").read_text(), "first")

    async def test_async_mapping_constructor_and_closed_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/a").write_bytes(b"data")
            client = syq.AsyncClient(executable=EXECUTABLE, process_cwd=root)
            async def entries():
                yield syq.MappingEntry("a", "renamed")
            mapping = syq.AsyncMapping(entries(), cwd=root / "source")
            await client.cp(mapping=mapping, into="destination")
            self.assertEqual((root / "destination/renamed").read_bytes(), b"data")
            async with client.map(srcs_in="source") as stream:
                transformed = stream.transform(lambda entry: entry)
            with self.assertRaisesRegex(syq.SyqInvocationError, "closed or exhausted"):
                await client.cp(mapping=transformed, into="closed")
            self.assertFalse((root / "closed").exists())

    async def test_async_failed_or_cancelled_transform_leaves_destination_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"data")
            client = syq.AsyncClient(executable=EXECUTABLE, process_cwd=root)
            async def fail(entry):
                raise LookupError("transform failed")
            async with client.map("a") as mapping:
                with self.assertRaisesRegex(LookupError, "transform failed"):
                    await client.cp(mapping=mapping.transform(fail), into="destination")
            self.assertFalse((root / "destination").exists())
            started = asyncio.Event()
            async def wait(entry):
                started.set()
                await asyncio.Event().wait()
                return entry
            async with client.map("a") as mapping:
                operation = asyncio.create_task(client.cp(mapping=mapping.transform(wait), into="destination"))
                await asyncio.wait_for(started.wait(), timeout=5)
                operation.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await operation
            self.assertFalse((root / "destination").exists())
