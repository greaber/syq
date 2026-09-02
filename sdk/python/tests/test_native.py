from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import syq


FAKE_NATIVE = r"""#!/usr/bin/env python3
import json
import os
import subprocess
import sys

args = sys.argv[1:]
marker = os.environ.get("SYQ_FAKE_DESCENDANT")
if marker:
    subprocess.Popen([
        sys.executable, "-c",
        "import pathlib,sys,time; time.sleep(0.6); pathlib.Path(sys.argv[1]).write_text('survived')",
        marker,
    ])
    open(marker + ".ready", "w").close()
log = os.environ.get("SYQ_FAKE_ARGV")
if log:
    with open(log, "w", encoding="utf-8") as output:
        json.dump(args, output)

command = args[0]
if command == "map":
    print(json.dumps({
        "src": {"encoding": "utf-8", "value": "a.txt"},
        "dst": {"encoding": "utf-8", "value": "a.txt"},
        "kind": "file", "size": 3, "mtime": 100,
    }))
    raise SystemExit(int(os.environ.get("SYQ_FAKE_EXIT", "0")))

dry_run = "--dry-run" in args
prune = "--prune" in args
records = [{
    "schema": "syq.automation", "schema_version": 1, "seq": 0,
    "type": "run", "run_id": "fake-run", "started_at": 123,
    "syq_version": "9.8.7", "mode": "cp", "prune": prune,
    "dry_run": dry_run, "mapping": "--mapping" in args,
    "endpoints": [
        {"role": "source", "kind": "local"},
        {"role": "destination", "kind": "ssh", "host": "target", "user": "u"},
    ],
}, {
    "schema": "syq.automation", "schema_version": 1, "seq": 1,
    "type": "progress", "bytes_done": 0, "bytes_total": 3,
    "bytes_unchanged": 0, "files_done": 0, "files_total": 1,
    "files_unchanged": 0, "files_excluded": 0, "scanned": 1,
    "scan_done": True, "elapsed_ms": 1,
}]
if os.environ.get("SYQ_FAKE_SHAPE") != "empty":
    if dry_run:
        records.append({
            "schema": "syq.automation", "schema_version": 1, "seq": 2,
            "type": "trace", "action": "transfer_file",
            "dst": {"encoding": "utf-8", "value": "a.txt"},
            "kind": "file", "reason": "destination_missing", "bytes": 3,
        })
    else:
        records.append({
            "schema": "syq.automation", "schema_version": 1, "seq": 2,
            "type": "operation_result", "action": "transfer_file",
            "dst": {"encoding": "utf-8", "value": "a.txt"},
            "kind": "file", "disposition": "succeeded", "bytes": 3,
            "attempts": 1,
        })
status = os.environ.get("SYQ_FAKE_STATUS", "success")
exit_code = 0 if status == "success" else 23
records.append({
    "schema": "syq.automation", "schema_version": 1, "seq": len(records),
    "type": "result", "status": status, "exit_code": exit_code,
    "dry_run": dry_run, "files_transferred": 1, "files_unchanged": 0,
    "files_excluded": 0, "directories_created": 0, "symlinks_created": 0,
    "specials_created": 0, "errors": 0 if status == "success" else 1,
    "bytes_transferred": 0 if dry_run else 3, "bytes_unchanged": 0,
    "elapsed_ms": 2,
})
if prune:
    records[-1].update({
        "deletions_planned": 1,
        "deletions_completed": 0 if dry_run else 1,
        "deletions_blocked": 0,
    })
shape = os.environ.get("SYQ_FAKE_SHAPE")
if shape == "bad-schema":
    records[0]["schema_version"] = 99
elif shape == "gap":
    records[-1]["seq"] += 1
elif shape == "truncated":
    records.pop()
elif shape == "partial-deletions":
    records[-1].pop("deletions_completed")
elif shape == "oversized-integer":
    records[-1]["files_transferred"] = 1 << 64
elif shape == "failed-operation":
    records[-2].update({
        "disposition": "failed", "retryable": "yes", "class": "io",
        "os_kind": "permission_denied", "message": "denied",
    })
elif shape == "unknown-event":
    records.insert(-1, {
        "schema": "syq.automation", "schema_version": 1,
        "seq": records[-1]["seq"], "type": "future_addition", "value": 1,
    })
    records[-1]["seq"] += 1
elif shape == "oversized-line":
    sys.stdout.buffer.write(b"x" * (16 * 1024 * 1024 + 1))
    sys.stdout.buffer.flush()
    raise SystemExit(0)
for record in records:
    print(json.dumps(record), flush=True)
raise SystemExit(exit_code)
"""


class NativeClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.executable = self.root / "syq"
        self.executable.write_text(FAKE_NATIVE, encoding="utf-8")
        self.executable.chmod(0o755)
        self.argv_log = self.root / "argv.json"
        self.env = {**os.environ, "SYQ_FAKE_ARGV": os.fspath(self.argv_log)}
        self.client = syq.Client(executable=self.executable, env=self.env)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def argv(self) -> list[str]:
        return json.loads(self.argv_log.read_text(encoding="utf-8"))

    def test_cp_uses_native_names_and_streams_v1_trace_events(self) -> None:
        events: list[syq.AutomationEvent] = []
        result = self.client.cp(
            src=["a", "b"],
            src_dir="assets",
            from_="source",
            follow=True,
            to="target",
            into_existing="out",
            prune=True,
            max_delete=10,
            dry_run=True,
            hash=True,
            no_compress=True,
            bwlimit="10M",
            connections=4,
            reuse_connection=True,
            max_entries=100,
            max_total_bytes="2G",
            max_runtime="30m",
            ignore=["*.tmp", "cache/"],
            ignore_from="ignore.txt",
            preserve=["permissions", "ownership"],
            inplace=True,
            max_size="2G",
            min_size=3,
            on_event=events.append,
        )

        self.assertIsInstance(result, syq.CpResult)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.files_transferred, 1)
        self.assertEqual(result.deletions_planned, 1)
        self.assertEqual(result.deletions_completed, 0)
        self.assertIs(events[-1], result)
        run = next(event for event in events if isinstance(event, syq.RunEvent))
        self.assertTrue(run.prune)
        self.assertEqual(run.endpoints[1].kind, syq.EndpointKind.SSH)
        self.assertTrue(any(isinstance(event, syq.ProgressEvent) for event in events))
        trace = next(event for event in events if isinstance(event, syq.TraceEvent))
        self.assertEqual(trace.action, syq.OperationAction.TRANSFER_FILE)
        self.assertEqual(trace.reason, syq.TraceReason.DESTINATION_MISSING)
        argv = self.argv()
        for expected in (
            "cp", "--src", "--src-dir", "--from", "--follow", "--to",
            "--into-existing", "--prune", "--max-delete", "--dry-run",
            "--hash", "--no-compress", "--bwlimit", "--connections",
            "--reuse-connection", "--max-entries", "--max-total-bytes",
            "--max-runtime", "--ignore", "--ignore-from", "--preserve",
            "--inplace", "--max-size", "--min-size", "--results=-",
        ):
            self.assertIn(expected, argv)
        self.assertNotIn("--quiet", argv)
        self.assertEqual(argv.count("--src"), 2)

    def test_live_cp_returns_operation_results(self) -> None:
        events: list[syq.AutomationEvent] = []
        result = self.client.cp("source", into="target", on_event=events.append)
        self.assertEqual(result.files_transferred, 1)
        operation = next(
            event for event in events if isinstance(event, syq.OperationResult)
        )
        self.assertEqual(operation.disposition, syq.Disposition.SUCCEEDED)
        self.assertEqual(operation.kind, syq.EntryKind.FILE)

    def test_cp_forwards_native_remote_controls(self) -> None:
        self.client.cp(
            "source",
            from_="source:2222",
            to="target:2200",
            into="out",
            run_at="local",
            rsh="ssh -F config",
            syq_path="/opt/syq",
            no_bootstrap=True,
            tcp_plain=True,
            tcp_ports="49000-49010",
            tcp_congestion="bbr",
        )
        argv = self.argv()
        for expected in (
            "--run-at",
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
                self.client.cp(
                    "source",
                    from_="source",
                    to="target",
                    into="out",
                    **parameter,
                )
                self.assertIn(option, self.argv())

    def test_non_success_result_raises_or_can_be_returned(self) -> None:
        env = {**self.env, "SYQ_FAKE_STATUS": "partial"}
        client = syq.Client(executable=self.executable, env=env)
        with self.assertRaises(syq.SyqOperationError) as caught:
            client.cp("source", into="target")
        self.assertEqual(caught.exception.result.status, syq.OperationStatus.PARTIAL)
        self.assertEqual(caught.exception.stderr, b"")
        result = client.cp("source", into="target", check=False)
        self.assertEqual(result.exit_code, 23)

    def test_failure_metadata_uses_mechanical_python_field_names(self) -> None:
        events: list[syq.AutomationEvent] = []
        client = syq.Client(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_STATUS": "partial",
                "SYQ_FAKE_SHAPE": "failed-operation",
            },
        )
        client.cp("source", into="target", check=False, on_event=events.append)
        operation = next(
            event for event in events if isinstance(event, syq.OperationResult)
        )
        self.assertIs(operation.class_, syq.ErrorClass.IO)
        self.assertIs(operation.os_kind, syq.OsKind.PERMISSION_DENIED)

    def test_protocol_rejects_unsupported_incomplete_and_gapped_streams(self) -> None:
        for shape, message in (
            ("bad-schema", "schema version"),
            ("gap", "sequence"),
            ("truncated", "terminal result"),
        ):
            with self.subTest(shape=shape):
                client = syq.Client(
                    executable=self.executable,
                    env={**self.env, "SYQ_FAKE_SHAPE": shape},
                )
                with self.assertRaisesRegex(syq.SyqProtocolError, message):
                    client.cp("source", into="target")

    def test_protocol_ignores_additive_record_types(self) -> None:
        client = syq.Client(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_SHAPE": "unknown-event"},
        )
        self.assertEqual(client.cp("source", into="target").exit_code, 0)

    def test_protocol_enforces_prune_totals_and_machine_value_bounds(self) -> None:
        cases = (
            ("partial-deletions", True, "every deletion total"),
            ("oversized-integer", False, "unsigned 64-bit range"),
            ("oversized-line", False, "larger than 16 MiB"),
        )
        for shape, prune, message in cases:
            with self.subTest(shape=shape):
                client = syq.Client(
                    executable=self.executable,
                    env={**self.env, "SYQ_FAKE_SHAPE": shape},
                )
                with self.assertRaisesRegex(syq.SyqProtocolError, message):
                    client.cp("source", into="target", prune=prune)

    def test_mapping_is_complete_before_the_copy_starts(self) -> None:
        self.argv_log.unlink(missing_ok=True)

        def broken():
            yield syq.MappingEntry("a", "a")
            raise RuntimeError("transform failed")

        with self.assertRaisesRegex(RuntimeError, "transform failed"):
            self.client.cp(mapping=broken(), cwd="source", into="target")
        self.assertFalse(self.argv_log.exists(), "copy started with a partial mapping")

    def test_mapping_serialization_preserves_raw_path_bytes(self) -> None:
        entry = syq.MappingEntry(b"raw-\xff", b"renamed-\xfe", syq.EntryKind.FILE)
        result = self.client.cp(mapping=[entry], cwd="source", into="target")
        self.assertTrue(result.status is syq.OperationStatus.SUCCESS)
        argv = self.argv()
        manifest = Path(argv[argv.index("--mapping") + 1])
        self.assertFalse(manifest.exists(), "temporary manifest survived the call")

    def test_map_is_streaming_typed_and_context_managed(self) -> None:
        with self.client.map(src_src="source", follow=True) as stream:
            entries = list(stream)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].src, syq.RelativePath("a.txt"))
        self.assertEqual(entries[0].kind, syq.EntryKind.FILE)
        self.assertEqual(self.argv()[0], "map")
        self.assertIn("--follow", self.argv())

    def test_structural_validation_happens_before_launch(self) -> None:
        with self.assertRaisesRegex(syq.SyqInvocationError, "exactly one"):
            self.client.cp("source")
        with self.assertRaisesRegex(syq.SyqInvocationError, "requires --prune"):
            self.client.cp("source", into="target", max_delete=1)
        with self.assertRaisesRegex(syq.SyqInvocationError, "conflicts"):
            self.client.cp(mapping="manifest", into="target", prune=True)
        with self.assertRaisesRegex(syq.SyqInvocationError, "ordinary source"):
            self.client.cp("a", "b", as_="target")
        with self.assertRaisesRegex(syq.SyqInvocationError, "ordinary source"):
            self.client.map(src_src="source", as_="target")
        with self.assertRaisesRegex(syq.SyqInvocationError, "--run-at"):
            self.client.cp("source", into="target", run_at="elsewhere")
        with self.assertRaisesRegex(ValueError, "relative"):
            syq.RelativePath("/absolute")
        with self.assertRaisesRegex(ValueError, "NUL"):
            syq.RelativePath(b"nul\0path")

    def test_callback_failure_kills_the_owned_process_group(self) -> None:
        marker = self.root / "descendant"
        client = syq.Client(
            executable=self.executable,
            env={**self.env, "SYQ_FAKE_DESCENDANT": os.fspath(marker)},
        )

        def fail(_event: syq.AutomationEvent) -> None:
            raise RuntimeError("callback failed")

        with self.assertRaisesRegex(RuntimeError, "callback failed"):
            client.cp("source", into="target", on_event=fail)
        self.assertTrue(marker.with_suffix(".ready").exists())
        time.sleep(0.8)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
