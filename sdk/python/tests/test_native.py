from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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
    descendant_delay = os.environ.get("SYQ_FAKE_DESCENDANT_DELAY", "0.6")
    subprocess.Popen([
        sys.executable, "-c",
        "import pathlib,sys,time; time.sleep(float(sys.argv[2])); pathlib.Path(sys.argv[1]).write_text('survived')",
        marker, descendant_delay,
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
       stderr=subprocess.DEVNULL)
    open(marker + ".ready", "w").close()
pause = os.environ.get("SYQ_FAKE_PAUSE")
if pause:
    time.sleep(float(pause))
log = os.environ.get("SYQ_FAKE_ARGV")
if log:
    with open(log, "w", encoding="utf-8") as output:
        json.dump(args, output)
stderr_bytes = int(os.environ.get("SYQ_FAKE_STDERR_BYTES", "0"))
if stderr_bytes:
    sys.stderr.buffer.write(b"x" * stderr_bytes)
    sys.stderr.buffer.flush()

results_fd = None
for arg in args:
    if arg.startswith("--results-fd="):
        results_fd = int(arg.split("=", 1)[1])
stream = os.fdopen(results_fd, "w") if results_fd is not None else sys.stdout

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
elif shape == "bad-endpoint-role":
    records[0]["endpoints"][0]["role"] = "observer"
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
    stream.buffer.write(b"x" * (16 * 1024 * 1024 + 1)) if stream is sys.stdout \
        else stream.write("x" * (16 * 1024 * 1024 + 1))
    stream.flush()
    raise SystemExit(0)
for record in records:
    print(json.dumps(record), file=stream, flush=True)
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
            root="source-root",
            follow_src=True,
            follow_dest=True,
            to="target",
            coordinate_at="local",
            into_existing="out",
            prune=True,
            max_delete=10,
            dry_run=True,
            hash=True,
            no_compress=True,
            bwlimit="10M",
            connections=4,
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
        self.assertEqual(run.endpoints[0].role, syq.EndpointRole.SOURCE)
        self.assertEqual(run.endpoints[1].role, syq.EndpointRole.DESTINATION)
        self.assertTrue(any(isinstance(event, syq.ProgressEvent) for event in events))
        trace = next(event for event in events if isinstance(event, syq.TraceEvent))
        self.assertEqual(trace.action, syq.OperationAction.TRANSFER_FILE)
        self.assertEqual(trace.reason, syq.TraceReason.DESTINATION_MISSING)
        argv = self.argv()
        for expected in (
            "cp", "--src", "--src-dir", "--from", "--root", "--follow-src",
            "--follow-dest", "--to",
            "--into-existing", "--prune", "--max-delete", "--dry-run",
            "--hash", "--no-compress", "--bwlimit", "--connections",
            "--max-entries", "--max-total-bytes",
            "--max-runtime", "--ignore", "--ignore-from", "--preserve",
            "--inplace", "--max-size", "--min-size",
        ):
            self.assertIn(expected, argv)
        self.assertTrue(
            any(arg.startswith("--results-fd=") for arg in argv),
            argv,
        )
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
        self.assertTrue(
            any(arg.startswith("--results-fd=") for arg in argv),
            argv,
        )

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
                    coordinate_at="local",
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
            ("bad-endpoint-role", "field 'role' is unsupported"),
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

    def test_streaming_stderr_is_bounded_without_a_temporary_spool(self) -> None:
        client = syq.Client(
            executable=self.executable,
            env={
                **self.env,
                "SYQ_FAKE_SHAPE": "truncated",
                "SYQ_FAKE_STDERR_BYTES": str(2 * 1024 * 1024),
            },
        )
        with mock.patch(
            "syq.client.tempfile.TemporaryFile",
            side_effect=AssertionError("stderr must not be spooled"),
        ):
            with self.assertRaises(syq.SyqProtocolError) as caught:
                client.cp("source", into="target")
        self.assertEqual(caught.exception.stderr, b"x" * 8192)

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

    def test_generated_mapping_path_resolves_temporary_directory_symlinks(self) -> None:
        physical = self.root / "physical-tmp"
        physical.mkdir()
        alias = self.root / "tmp-alias"
        alias.symlink_to(physical, target_is_directory=True)
        named_temporary_file = tempfile.NamedTemporaryFile

        def create_through_alias(**kwargs):
            return named_temporary_file(dir=alias, **kwargs)

        with mock.patch(
            "syq.client.tempfile.NamedTemporaryFile",
            side_effect=create_through_alias,
        ):
            self.client.cp(
                mapping=[syq.MappingEntry("a", "a")],
                cwd="source",
                into="target",
            )
        argv = self.argv()
        manifest = Path(argv[argv.index("--mapping") + 1])
        self.assertEqual(manifest.parent, physical.resolve())

    def test_ignore_stream_preserves_native_cross_option_order(self) -> None:
        self.client.cp(
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

    def test_map_is_streaming_typed_and_context_managed(self) -> None:
        with self.client.map(
            src_src="source", root="source-root", follow_src=True
        ) as stream:
            entries = list(stream)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].src, syq.RelativePath("a.txt"))
        self.assertEqual(entries[0].kind, syq.EntryKind.FILE)
        self.assertEqual(self.argv()[0], "map")
        self.assertIn("--root", self.argv())
        self.assertIn("--follow-src", self.argv())
        self.assertEqual(stream.cwd, Path.cwd() / "source-root" / "source")

    def test_map_cwd_preserves_the_unresolved_source_spelling(self) -> None:
        base = self.root / "base"
        outside = self.root / "outside"
        base.mkdir()
        outside.mkdir()
        (base / "link").symlink_to(outside, target_is_directory=True)
        client = syq.Client(
            executable=self.executable,
            env=self.env,
            process_cwd=self.root,
        )
        with client.map(
            src_src="link/../selected", cwd="base", follow_src=True
        ) as stream:
            list(stream)
        self.assertEqual(
            os.fspath(stream.cwd),
            os.path.join(os.fspath(self.root), "base", "link/../selected"),
        )

    def test_map_cwd_expands_tilde_with_the_subprocess_home(self) -> None:
        home = self.root / "native-home"
        client = syq.Client(
            executable=self.executable,
            env={**self.env, "HOME": os.fspath(home)},
            process_cwd=self.root,
        )
        with client.map(src_src="~/selected", cwd="ignored") as stream:
            list(stream)
        self.assertEqual(stream.cwd, home / "selected")

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
        with self.assertRaisesRegex(syq.SyqInvocationError, "mutually exclusive"):
            self.client.cp("source", cwd="a", root="b", into="target")
        with self.assertRaisesRegex(syq.SyqInvocationError, "mutually exclusive"):
            self.client.map("source", cwd="a", root="b")
        with self.assertRaisesRegex(syq.SyqInvocationError, "--coordinate-at"):
            self.client.cp("source", into="target", coordinate_at="elsewhere")
        with self.assertRaisesRegex(syq.SyqInvocationError, "dry run"):
            self.client.cp(from_="alpha:src", to="beta:dst", dry_run=True)
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


class ReceiverAttestedDecodingTests(unittest.TestCase):
    @staticmethod
    def _final_state_decoder():
        from syq.protocol import AutomationDecoder

        decoder = AutomationDecoder(prune=False, mapping=False, dry_run=False)
        decoder.feed(
            json.dumps(
                {
                    "schema": "syq.automation",
                    "schema_version": 1,
                    "seq": 0,
                    "type": "run",
                    "run_id": "attested",
                    "started_at": 1,
                    "syq_version": "0.0.0",
                    "mode": "cp",
                    "prune": False,
                    "mapping": False,
                    "dry_run": False,
                    "endpoints": [
                        {"role": "source", "kind": "ssh", "host": "a"},
                        {"role": "destination", "kind": "ssh", "host": "b"},
                    ],
                }
            ).encode()
        )
        return decoder

    @staticmethod
    def _final_state(metadata=None, digest=None):
        record = {
            "schema": "syq.automation",
            "schema_version": 1,
            "seq": 1,
            "type": "final_state",
            "provenance": "receiver_attested",
            "scope": 0,
            "dst": {"encoding": "utf-8", "value": "tree/file"},
            "object": {
                "state": "present",
                "kind": "file",
                "size": 3,
                "metadata": metadata
                or {
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "mtime": 1,
                    "mtime_nsec": 0,
                    "rdev": 0,
                },
            },
        }
        if digest is not None:
            record["object"]["digest"] = digest
        return json.dumps(record).encode()

    def test_signed_mtimes_decode_and_bad_digests_are_rejected(self) -> None:
        # A pre-1970 mtime is schema-valid signed data.
        decoder = self._final_state_decoder()
        event = decoder.feed(
            self._final_state(
                metadata={
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "mtime": -1,
                    "mtime_nsec": 0,
                    "rdev": 0,
                }
            )
        )
        assert event.metadata is not None
        self.assertEqual(event.metadata.mtime, -1)

        for digest in (
            {"algorithm": "sha256", "value": "ab" * 32},
            {"algorithm": "blake3", "value": "not-hex"},
            {"algorithm": "blake3", "value": "AB" * 32},
        ):
            decoder = self._final_state_decoder()
            with self.assertRaises(syq.SyqProtocolError):
                decoder.feed(self._final_state(digest=digest))

    @staticmethod
    def _terminal(seq=1, **overrides):
        record = {
            "schema": "syq.automation",
            "schema_version": 1,
            "seq": seq,
            "type": "result",
            "status": "success",
            "exit_code": 0,
            "dry_run": False,
            "files_transferred": 0,
            "files_unchanged": 0,
            "files_excluded": 0,
            "directories_created": 0,
            "symlinks_created": 0,
            "specials_created": 0,
            "errors": 0,
            "bytes_transferred": 0,
            "bytes_unchanged": 0,
            "elapsed_ms": 1,
        }
        record.update(overrides)
        return json.dumps({k: v for k, v in record.items() if v is not ...}).encode()

    def test_final_state_variants_are_enforced(self) -> None:
        metadata = {
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "mtime": 1,
            "mtime_nsec": 0,
            "rdev": 0,
        }
        base = {
            "schema": "syq.automation",
            "schema_version": 1,
            "seq": 1,
            "type": "final_state",
            "provenance": "receiver_attested",
            "scope": 0,
            "dst": {"encoding": "utf-8", "value": "tree/file"},
        }
        bad_objects = [
            # present without its required attestation fields
            {"state": "present", "kind": "file", "size": 3},
            # absent smuggling present-only fields
            {"state": "absent", "size": 3},
            # observation_failed without its code
            {"state": "observation_failed", "message": "hash failed"},
            # a kind outside the receiver vocabulary
            {
                "state": "present",
                "kind": "wormhole",
                "size": 3,
                "metadata": metadata,
            },
        ]
        for bad in bad_objects:
            decoder = self._final_state_decoder()
            with self.assertRaises(syq.SyqProtocolError):
                decoder.feed(json.dumps({**base, "object": bad}).encode())

        # The full receiver vocabulary of kinds decodes.
        decoder = self._final_state_decoder()
        event = decoder.feed(
            json.dumps(
                {
                    **base,
                    "object": {
                        "state": "present",
                        "kind": "character_device",
                        "size": 0,
                        "metadata": metadata,
                    },
                }
            ).encode()
        )
        self.assertIs(event.kind, syq.FinalObjectKind.CHARACTER_DEVICE)

    def test_unknown_final_state_fields_stay_additive(self) -> None:
        # Additive optional fields from a future minor version are ignored;
        # only known fields on the wrong variant are protocol errors.
        decoder = self._final_state_decoder()
        record = json.loads(self._final_state())
        record["object"]["future_attestation"] = {"v": 2}
        event = decoder.feed(json.dumps(record).encode())
        self.assertIs(event.state, syq.FinalObjectState.PRESENT)

    def test_attested_operation_and_error_fields_are_discriminated(self) -> None:
        base = {
            "schema": "syq.automation",
            "schema_version": 1,
            "seq": 1,
        }
        operation = {
            **base,
            "type": "operation_result",
            "action": "transfer_file",
            "dst": {"encoding": "utf-8", "value": "tree/file"},
            "kind": "file",
            "disposition": "succeeded",
        }
        bad_records = [
            # provenance from nowhere
            {**operation, "provenance": "self_reported", "scope": 0},
            # receipt fields without attested provenance
            {**operation, "scope": 0},
            {**operation, "code": "execution_failed"},
            # attested operations always carry their scope
            {**operation, "provenance": "receiver_attested"},
            # receipt code on an ordinary error record
            {
                **base,
                "type": "error",
                "message": "boom",
                "code": "execution_failed",
            },
            {
                **base,
                "type": "error",
                "message": "boom",
                "provenance": "self_reported",
            },
        ]
        for bad in bad_records:
            decoder = self._final_state_decoder()
            with self.assertRaises(syq.SyqProtocolError):
                decoder.feed(json.dumps(bad).encode())

        # An attested error's code is optional: a partial observation has none.
        decoder = self._final_state_decoder()
        event = decoder.feed(
            json.dumps(
                {
                    **base,
                    "type": "error",
                    "message": "partly observed",
                    "class": "io",
                    "provenance": "receiver_attested",
                }
            ).encode()
        )
        self.assertEqual(event.provenance, "receiver_attested")
        self.assertIsNone(event.code)

    def test_attested_terminals_are_discriminated(self) -> None:
        attested = {
            "provenance": "receiver_attested",
            "receipt_status": "clean",
            "operations": 0,
            "final_states": 0,
            "receipt_records": 1,
            "deletions_completed": 0,
        }
        bad_terminals = [
            # receipt_status outside the verified vocabulary
            {**attested, "receipt_status": "garbage"},
            # attested without its bookkeeping
            {"provenance": "receiver_attested", "receipt_status": "clean"},
            # attested without its settled-deletion total
            {**attested, "deletions_completed": ...},
            # provenance from nowhere
            {**attested, "provenance": "self_reported"},
            # ordinary result smuggling receipt bookkeeping
            {"receipt_status": "clean"},
            {"operations": 3},
        ]
        for bad in bad_terminals:
            decoder = self._final_state_decoder()
            with self.assertRaises(syq.SyqProtocolError):
                decoder.feed(self._terminal(**bad))

        decoder = self._final_state_decoder()
        result = decoder.feed(self._terminal(**attested))
        self.assertIs(result.receipt_status, syq.ReceiptStatus.CLEAN)
        self.assertEqual(result.receipt_records, 1)

    def test_attested_records_decode_with_the_receiver_vocabulary(self) -> None:
        from syq.protocol import AutomationDecoder

        decoder = AutomationDecoder(prune=True, mapping=False, dry_run=False)
        envelope = {"schema": "syq.automation", "schema_version": 1}
        records = [
            {
                **envelope,
                "seq": 0,
                "type": "run",
                "run_id": "attested",
                "started_at": 1,
                "syq_version": "0.0.0",
                "mode": "cp",
                "prune": True,
                "mapping": False,
                "dry_run": False,
                "endpoints": [
                    {"role": "source", "kind": "ssh", "host": "a"},
                    {"role": "destination", "kind": "ssh", "host": "b"},
                ],
            },
            {
                **envelope,
                "seq": 1,
                "type": "operation_result",
                "provenance": "receiver_attested",
                "action": "set_metadata",
                "scope": 0,
                "dst": {"encoding": "utf-8", "value": "tree"},
                "disposition": "succeeded",
            },
            {
                **envelope,
                "seq": 2,
                "type": "operation_result",
                "provenance": "receiver_attested",
                "action": "observe_hash",
                "kind": "file",
                "scope": 0,
                "dst": {"encoding": "utf-8", "value": "tree/a"},
                "disposition": "observed",
            },
            {
                **envelope,
                "seq": 3,
                "type": "final_state",
                "provenance": "receiver_attested",
                "scope": 0,
                "dst": {"encoding": "utf-8", "value": "tree/a"},
                "object": {
                    "state": "present",
                    "kind": "file",
                    "size": 3,
                    "metadata": {
                        "mode": 0o644,
                        "uid": 0,
                        "gid": 0,
                        "mtime": 1,
                        "mtime_nsec": 0,
                        "rdev": 0,
                    },
                    "digest": {"algorithm": "blake3", "value": "ab" * 32},
                },
            },
            {
                **envelope,
                "seq": 4,
                "type": "result",
                "provenance": "receiver_attested",
                "receipt_status": "clean",
                "status": "success",
                "exit_code": 0,
                "dry_run": False,
                "files_transferred": 1,
                "files_unchanged": 0,
                "files_excluded": 0,
                "directories_created": 0,
                "symlinks_created": 0,
                "specials_created": 0,
                "errors": 0,
                "bytes_transferred": 3,
                "bytes_unchanged": 0,
                "elapsed_ms": 5,
                "deletions_completed": 0,
                "operations": 3,
                "final_states": 1,
                "receipt_records": 4,
            },
        ]
        events = [
            decoder.feed(json.dumps(record).encode()) for record in records
        ]
        metadata = events[1]
        self.assertIsInstance(metadata, syq.OperationResult)
        self.assertIs(metadata.action, syq.OperationAction.SET_METADATA)
        self.assertIsNone(metadata.kind)
        self.assertEqual(metadata.provenance, "receiver_attested")
        observed = events[2]
        self.assertIs(observed.disposition, syq.Disposition.OBSERVED)
        final = events[3]
        self.assertIsInstance(final, syq.FinalStateEvent)
        self.assertIs(final.state, syq.FinalObjectState.PRESENT)
        assert final.digest is not None
        self.assertEqual(final.digest.algorithm, "blake3")
        self.assertEqual(final.digest.value, "ab" * 32)
        assert final.metadata is not None
        self.assertEqual(final.metadata.mode, 0o644)
        result = decoder.finish(0)
        # Attested terminals carry only the settled-deletion total.
        self.assertIsNone(result.deletions_planned)
        self.assertIsNone(result.deletions_blocked)
        self.assertEqual(result.deletions_completed, 0)
        self.assertEqual(result.receipt_status, "clean")
        self.assertEqual(result.operations, 3)
        self.assertEqual(result.final_states, 1)
        self.assertEqual(result.receipt_records, 4)
