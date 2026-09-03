from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import syq

try:
    from test_native import FAKE_NATIVE
except ModuleNotFoundError:
    from sdk.python.tests.test_native import FAKE_NATIVE


RAW_PROCESS = r"""#!/usr/bin/env python3
import sys
import time

time.sleep(0.15)
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(data.upper())
"""


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.executable = self.root / "syq"
        self.executable.write_text(FAKE_NATIVE, encoding="utf-8")
        self.executable.chmod(0o755)
        self.argv_log = self.root / "argv.json"
        self.env = {**os.environ, "SYQ_FAKE_ARGV": os.fspath(self.argv_log)}
        self.client = syq.AsyncClient(executable=self.executable, env=self.env)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def argv(self) -> list[str]:
        return json.loads(self.argv_log.read_text(encoding="utf-8"))

    async def test_typed_methods_accept_async_callbacks(self) -> None:
        events: list[syq.AutomationEvent] = []

        async def observe(event: syq.AutomationEvent) -> None:
            await asyncio.sleep(0)
            events.append(event)

        result = await self.client.cp(
            src=["a", "b"],
            src_dir="assets",
            from_="source",
            root="source-root",
            follow_src=True,
            follow_dest=True,
            to="target",
            coordinate_at="local",
            into_existing="out",
            dry_run=True,
            hash=True,
            max_entries=100,
            max_total_bytes="2G",
            max_runtime="30m",
            on_event=observe,
        )

        self.assertIsInstance(result, syq.CpResult)
        self.assertTrue(result.dry_run)
        self.assertIs(events[-1], result)
        self.assertTrue(any(isinstance(event, syq.TraceEvent) for event in events))
        self.assertTrue(
            any(arg.startswith("--results-fd=") for arg in self.argv()),
            self.argv(),
        )
        self.assertNotIn("--quiet", self.argv())
        self.assertIn("--root", self.argv())
        self.assertIn("--follow-src", self.argv())
        self.assertIn("--follow-dest", self.argv())
        self.assertIn("--max-entries", self.argv())
        self.assertIn("--max-total-bytes", self.argv())
        self.assertIn("--max-runtime", self.argv())
        self.assertEqual(self.argv().count("--src"), 2)

        prune = await self.client.cp(
            src_src="source", into="target", prune=True, max_delete=10
        )
        self.assertIsInstance(prune, syq.CpResult)
        self.assertEqual(prune.deletions_completed, 1)

    async def test_map_is_a_lazy_async_context_managed_stream(self) -> None:
        stream = self.client.map(
            src_src="source", root="source-root", follow_src=True
        )
        self.assertFalse(self.argv_log.exists(), "map started before it was consumed")
        async with stream:
            deadline = time.monotonic() + 2
            while not self.argv_log.exists():
                if time.monotonic() >= deadline:
                    self.fail("fake syq map did not record its arguments")
                await asyncio.sleep(0.01)
            self.assertIn("--follow-src", self.argv())
            self.assertIn("--root", self.argv())
            copied = await self.client.cp(
                mapping=stream, cwd=stream.cwd, into="target"
            )
        self.assertEqual(copied.files_transferred, 1)
        self.assertEqual(stream.cwd, Path.cwd() / "source-root" / "source")
        self.assertEqual(self.argv()[0], "cp")

    async def test_map_cwd_preserves_the_unresolved_source_spelling(self) -> None:
        actual = self.root / "actual"
        actual.mkdir()
        (self.root / "root-link").symlink_to(actual, target_is_directory=True)
        client = syq.AsyncClient(
            executable=self.executable,
            env=self.env,
            process_cwd=self.root,
        )
        stream = client.map(src_src="selected", root="root-link", follow_src=True)
        async with stream:
            entries = [entry async for entry in stream]
        self.assertEqual(len(entries), 1)
        self.assertEqual(stream.cwd, self.root / "root-link" / "selected")

    async def test_cp_forwards_native_remote_controls(self) -> None:
        await self.client.cp(
            "source",
            from_="source:2222",
            to="target:2200",
            into="out",
            coordinate_at="local",
            rsh="ssh -F config",
            syq_path="/opt/syq",
            no_bootstrap=True,
            tcp_plain=True,
            tcp_ports="49000-49010",
            tcp_congestion="bbr",
        )
        argv = self.argv()
        for expected in (
            "--coordinate-at",
            "--rsh",
            "--syq-path",
            "--no-bootstrap",
            "--tcp-plain",
            "--tcp-ports",
            "--tcp-congestion",
        ):
            self.assertIn(expected, argv)

        for parameter, option in (
            ({"no_tcp": True}, "--no-tcp"),
            ({"no_forward_agent": True}, "--no-forward-agent"),
            (
                {"unrestricted_agent_forwarding": True},
                "--unrestricted-agent-forwarding",
            ),
            ({"agent_broker_only": True}, "--agent-broker-only"),
        ):
            with self.subTest(option=option):
                await self.client.cp(
                    "source",
                    from_="source",
                    to="target",
                    coordinate_at="local",
                    into="out",
                    **parameter,
                )
                self.assertIn(option, self.argv())

    async def test_mapping_failure_happens_before_process_start(self) -> None:
        self.argv_log.unlink(missing_ok=True)

        def broken():
            yield syq.MappingEntry("a", "a")
            raise RuntimeError("transform failed")

        with self.assertRaisesRegex(RuntimeError, "transform failed"):
            await self.client.cp(mapping=broken(), cwd="source", into="target")
        self.assertFalse(self.argv_log.exists())

    async def test_generated_mapping_path_resolves_temp_directory_symlinks(
        self,
    ) -> None:
        physical = self.root / "physical-tmp"
        physical.mkdir()
        alias = self.root / "tmp-alias"
        alias.symlink_to(physical, target_is_directory=True)
        named_temporary_file = tempfile.NamedTemporaryFile

        def create_through_alias(**kwargs):
            return named_temporary_file(dir=alias, **kwargs)

        with mock.patch(
            "syq.async_client.tempfile.NamedTemporaryFile",
            side_effect=create_through_alias,
        ):
            await self.client.cp(
                mapping=[syq.MappingEntry("a", "a")],
                cwd="source",
                into="target",
            )
        argv = self.argv()
        manifest = Path(argv[argv.index("--mapping") + 1])
        self.assertEqual(manifest.parent, physical.resolve())

    async def test_ignore_stream_preserves_native_cross_option_order(self) -> None:
        await self.client.cp(
            "source",
            into="target",
            ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"],
        )
        argv = self.argv()
        start = argv.index("--ignore-from")
        self.assertEqual(
            argv[start : start + 4],
            ["--ignore-from", "rules", "--ignore", "!keep.tmp"],
        )

    async def test_cancelling_sync_mapping_stops_after_current_entry(self) -> None:
        started = threading.Event()
        yielded = 0

        def slow_mapping():
            nonlocal yielded
            for index in range(5):
                started.set()
                time.sleep(0.2)
                yielded += 1
                yield syq.MappingEntry(f"{index}", f"{index}")

        task = asyncio.create_task(
            self.client.cp(
                mapping=slow_mapping(), cwd="source", into="target"
            )
        )
        deadline = time.monotonic() + 2
        while not started.is_set():
            if time.monotonic() >= deadline:
                self.fail("mapping materialization did not start")
            await asyncio.sleep(0.01)

        started_at = time.monotonic()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertLess(time.monotonic() - started_at, 0.7)
        self.assertLess(yielded, 5)
        self.assertFalse(self.argv_log.exists())

    async def test_additive_events_are_not_delivered_as_none(self) -> None:
        events: list[syq.AutomationEvent] = []
        client = syq.AsyncClient(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_SHAPE": "unknown-event"},
        )
        await client.cp("source", into="target", on_event=events.append)
        self.assertTrue(events)
        self.assertNotIn(None, events)

    async def test_oversized_machine_record_is_rejected(self) -> None:
        client = syq.AsyncClient(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_SHAPE": "oversized-line"},
        )
        with self.assertRaisesRegex(syq.SyqProtocolError, "exceeds"):
            await client.cp("source", into="target")

    async def test_streaming_stderr_is_bounded_without_a_temporary_spool(
        self,
    ) -> None:
        client = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_SHAPE": "truncated",
                "SYQ_FAKE_STDERR_BYTES": str(2 * 1024 * 1024),
            },
        )
        with mock.patch(
            "syq.async_client.tempfile.TemporaryFile",
            side_effect=AssertionError("stderr must not be spooled"),
        ):
            with self.assertRaises(syq.SyqProtocolError) as caught:
                await client.cp("source", into="target")
        self.assertEqual(caught.exception.stderr, b"x" * 8192)

    async def test_protocol_failure_kills_post_exit_descendants(self) -> None:
        marker = self.root / "protocol-descendant"
        client = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_DESCENDANT_DELAY": "0.6",
                "SYQ_FAKE_SHAPE": "truncated",
            },
        )
        with self.assertRaisesRegex(syq.SyqProtocolError, "terminal result"):
            await client.cp("source", into="target")
        self.assertTrue(marker.with_suffix(".ready").exists())
        await asyncio.sleep(0.8)
        self.assertFalse(marker.exists())

    async def test_early_map_context_exit_kills_the_process_group(self) -> None:
        marker = self.root / "map-descendant"
        client = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_PAUSE": "10",
            },
        )
        async with client.map(src_src="source"):
            deadline = time.monotonic() + 2
            while not marker.with_suffix(".ready").exists():
                if time.monotonic() >= deadline:
                    self.fail("fake syq map did not become ready")
                await asyncio.sleep(0.01)

        await asyncio.sleep(0.8)
        self.assertFalse(marker.exists())

    async def test_raw_run_does_not_block_the_event_loop(self) -> None:
        executable = self.root / "raw-process"
        executable.write_text(RAW_PROCESS, encoding="utf-8")
        executable.chmod(0o755)
        client = syq.AsyncClient(executable=executable)

        task = asyncio.create_task(client.run(["ignored"], input=b"payload"))
        await asyncio.sleep(0.02)
        self.assertFalse(task.done())
        result = await task
        self.assertEqual(result.stdout, b"PAYLOAD")

    async def test_cancellation_kills_and_reaps_the_process_group(self) -> None:
        marker = self.root / "descendant"
        client = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_PAUSE": "10",
            },
        )
        task = asyncio.create_task(client.cp("source", into="target"))
        deadline = time.monotonic() + 2
        while not marker.with_suffix(".ready").exists():
            if time.monotonic() >= deadline:
                self.fail("fake syq did not become ready before cancellation")
            await asyncio.sleep(0.01)

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.8)
        self.assertFalse(marker.exists())

    async def test_timeout_kills_and_reaps_the_process_group(self) -> None:
        marker = self.root / "timed-out-descendant"
        client = syq.AsyncClient(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_DESCENDANT": os.fspath(marker),
                "SYQ_FAKE_DESCENDANT_DELAY": "2",
                "SYQ_FAKE_PAUSE": "10",
            },
            timeout=1.0,
        )

        with self.assertRaises(asyncio.TimeoutError):
            await client.cp("source", into="target")
        self.assertTrue(marker.with_suffix(".ready").exists())
        await asyncio.sleep(1.2)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
