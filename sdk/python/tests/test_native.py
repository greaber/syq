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
import time

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

mode = command
dry_run = "--dry-run" in args
run_id = "fake-run"
records = [{
    "schema": "syq.automation", "schema_version": 1,
    "run_id": run_id, "seq": 0, "elapsed_ms": 0,
    "type": "run", "syq_version": "9.8.7", "mode": mode,
    "dry_run": dry_run, "mapping": "--mapping" in args,
}]
if os.environ.get("SYQ_FAKE_SHAPE") != "empty":
    records.append({
        "schema": "syq.automation", "schema_version": 1,
        "run_id": run_id, "seq": 1, "elapsed_ms": 1,
        "type": "operation_result",
        "action": "remove" if command == "rm" else "transfer_file",
        "dst": {"encoding": "utf-8", "value": "a.txt", "display": "a.txt"},
        "kind": "unknown" if command == "rm" else "file",
        "disposition": "planned" if dry_run else "succeeded",
        "bytes": 3 if command != "rm" else 0,
    })
status = os.environ.get("SYQ_FAKE_STATUS", "success")
exit_code = 0 if status == "success" else 23
seq = len(records)
records.append({
    "schema": "syq.automation", "schema_version": 1,
    "run_id": run_id, "seq": seq, "elapsed_ms": 2,
    "type": "result", "status": status, "exit_code": exit_code,
    "files_planned": 0 if command == "rm" else 1,
    "files_completed": 0 if dry_run or command == "rm" else 1,
    "files_unchanged": 0, "files_excluded": 0,
    "directories_planned": 0, "directories_completed": 0,
    "symlinks_planned": 0, "symlinks_completed": 0,
    "specials_planned": 0, "specials_completed": 0,
    "deletions_planned": 1 if command == "rm" else 0,
    "deletions_completed": 1 if command == "rm" and not dry_run else 0,
    "deletions_blocked": False, "errors": 0 if status == "success" else 1,
    "bytes_planned": 0 if command == "rm" else 3,
    "bytes_completed": 0 if dry_run or command == "rm" else 3,
    "bytes_unchanged": 0,
})
shape = os.environ.get("SYQ_FAKE_SHAPE")
if shape == "bad-schema":
    records[0]["schema_version"] = 99
elif shape == "gap":
    records[-1]["seq"] += 1
elif shape == "truncated":
    records.pop()
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

    def test_cp_uses_native_names_and_streams_typed_events(self) -> None:
        events: list[syq.AutomationEvent] = []
        result = self.client.cp(
            src=["a", "b"],
            src_dir="assets",
            from_="source",
            follow=True,
            to="target",
            into_existing="out",
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
        self.assertEqual(result.files_planned, 1)
        self.assertEqual(result.files_completed, 0)
        self.assertIs(events[-1], result)
        operation = next(
            event for event in events if isinstance(event, syq.OperationResult)
        )
        self.assertEqual(operation.disposition, syq.Disposition.PLANNED)
        argv = self.argv()
        for expected in (
            "cp", "--src", "--src-dir", "--from", "--follow", "--to",
            "--into-existing", "--dry-run", "--hash", "--no-compress",
            "--bwlimit", "--connections", "--reuse-connection", "--max-entries",
            "--max-total-bytes", "--max-runtime", "--ignore", "--ignore-from",
            "--preserve", "--inplace", "--max-size", "--min-size",
            "--results=-", "--quiet",
        ):
            self.assertIn(expected, argv)
        self.assertEqual(argv.count("--src"), 2)

    def test_cp_prune_and_rm_have_command_specific_results(self) -> None:
        prune = self.client.cp_prune(
            src_src="source", into="target", max_delete=10
        )
        self.assertIsInstance(prune, syq.CpPruneResult)
        self.assertEqual(self.argv()[0], "cp-prune")
        self.assertIn("--max-delete", self.argv())

        removal = self.client.rm(
            src_dir=["a", "b"], root="safe", follow=True, dry_run=True
        )
        self.assertIsInstance(removal, syq.RmResult)
        self.assertEqual(removal.deletions_planned, 1)
        self.assertIn("--root", self.argv())
        self.assertIn("--follow", self.argv())

    def test_non_success_result_raises_or_can_be_returned(self) -> None:
        env = {**self.env, "SYQ_FAKE_STATUS": "partial"}
        client = syq.Client(executable=self.executable, env=env)
        with self.assertRaises(syq.SyqOperationError) as caught:
            client.cp("source", into="target")
        self.assertEqual(caught.exception.result.status, syq.OperationStatus.PARTIAL)
        self.assertEqual(caught.exception.stderr, b"")
        result = client.cp("source", into="target", check=False)
        self.assertEqual(result.exit_code, 23)

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
        with self.assertRaisesRegex(syq.SyqInvocationError, "conflicts"):
            self.client.rm("source", cwd="a", root="b")
        with self.assertRaisesRegex(syq.SyqInvocationError, "ordinary source"):
            self.client.cp("a", "b", as_="target")
        with self.assertRaisesRegex(syq.SyqInvocationError, "ordinary source"):
            self.client.map(src_src="source", as_="target")
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
