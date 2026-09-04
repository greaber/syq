from __future__ import annotations

import json
import unittest
from pathlib import Path

import syq
from syq.protocol import AutomationDecoder


FIXTURES = Path(__file__).resolve().parents[3] / "tests/fixtures/automation-v1"


@unittest.skipUnless(FIXTURES.is_dir(), "repository automation fixtures unavailable")
class AutomationFixtureTests(unittest.TestCase):
    def test_every_product_fixture_decodes_with_the_python_consumer(self) -> None:
        cases = {
            "dry-run.ndjson": ("cp", False, True, True, 0, None),
            "failed.ndjson": ("cp", False, False, False, 1, None),
            "partial.ndjson": ("cp", False, True, False, 23, None),
            "refused.ndjson": ("cp", True, False, False, 25, None),
            "success.ndjson": ("cp", False, True, False, 0, None),
            "rm-dry-partial.ndjson": ("rm", False, False, True, 23, 1),
            "rm-dry-run.ndjson": ("rm", False, False, True, 0, 1),
            "rm-failed.ndjson": ("rm", False, False, False, 1, 1),
            "rm-partial.ndjson": ("rm", False, False, False, 23, 1),
            "rm-success.ndjson": ("rm", False, False, False, 0, 2),
        }
        self.assertEqual(
            {path.name for path in FIXTURES.glob("*.ndjson")},
            set(cases),
            "classify every committed automation-v1 fixture",
        )

        for name, (
            mode,
            prune,
            mapping,
            dry_run,
            returncode,
            selectors_total,
        ) in cases.items():
            with self.subTest(fixture=name):
                decoder = AutomationDecoder(
                    mode=mode,
                    prune=prune,
                    mapping=mapping,
                    dry_run=dry_run,
                    selectors_total=selectors_total,
                )
                events = [
                    event
                    for line in (FIXTURES / name).read_bytes().splitlines()
                    if (event := decoder.feed(line)) is not None
                ]
                result = decoder.finish(returncode)
                self.assertIsInstance(events[0], syq.RunEvent)
                self.assertIs(events[-1], result)
                self.assertIsInstance(
                    result, syq.CpResult if mode == "cp" else syq.RmResult
                )
                if mode == "cp" and dry_run:
                    self.assertEqual(result.bytes_transferred, 8)

    def test_rm_progress_and_dry_run_failures_are_valid_events(self) -> None:
        decoder = AutomationDecoder(mode="rm", dry_run=True, selectors_total=1)
        events = [
            decoder.feed(line)
            for line in (FIXTURES / "rm-dry-partial.ndjson")
            .read_bytes()
            .splitlines()
        ]
        self.assertIsInstance(events[2], syq.RemovalResult)
        self.assertIs(decoder.finish(23), events[-1])

        records = [
            json.loads(line)
            for line in (FIXTURES / "rm-success.ndjson").read_bytes().splitlines()
        ]
        for record in records[1:]:
            record["seq"] += 1
        records.insert(
            1,
            {
                "schema": "syq.automation",
                "schema_version": 1,
                "seq": 1,
                "type": "progress",
                "bytes_done": 0,
                "bytes_total": 0,
                "bytes_unchanged": 0,
                "files_done": 0,
                "files_total": 0,
                "files_unchanged": 0,
                "files_excluded": 0,
                "scanned": 0,
                "scan_done": True,
                "elapsed_ms": 1,
            },
        )
        decoder = AutomationDecoder(
            mode="rm", dry_run=False, selectors_total=2
        )
        events = [decoder.feed(json.dumps(record).encode()) for record in records]
        self.assertIsInstance(events[1], syq.ProgressEvent)
        decoder.finish(0)

    def test_rm_terminal_counters_are_checked_against_events(self) -> None:
        records = [
            json.loads(line)
            for line in (FIXTURES / "rm-success.ndjson").read_bytes().splitlines()
        ]
        records[-1]["entries_removed"] += 1
        decoder = AutomationDecoder(
            mode="rm", dry_run=False, selectors_total=2
        )
        for record in records[:-1]:
            decoder.feed(json.dumps(record).encode())
        with self.assertRaisesRegex(syq.SyqProtocolError, "entries_removed"):
            decoder.feed(json.dumps(records[-1]).encode())

        partial = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        partial_events = [
            event
            for line in (FIXTURES / "partial.ndjson").read_bytes().splitlines()
            if (event := partial.feed(line)) is not None
        ]
        operation = next(
            event
            for event in partial_events
            if isinstance(event, syq.OperationResult)
            and event.disposition is syq.Disposition.FAILED
        )
        self.assertIs(operation.class_, syq.ErrorClass.IO)
        self.assertIs(operation.os_kind, syq.OsKind.NOT_FOUND)
        self.assertEqual(
            operation.retry_entry(),
            syq.MappingEntry("missing.txt", "missing.txt", "file"),
        )


if __name__ == "__main__":
    unittest.main()
