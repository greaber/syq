from __future__ import annotations

import unittest
from pathlib import Path

import syq
from syq.protocol import AutomationDecoder


FIXTURES = Path(__file__).resolve().parents[3] / "tests/fixtures/automation-v1"


@unittest.skipUnless(FIXTURES.is_dir(), "repository automation fixtures unavailable")
class AutomationFixtureTests(unittest.TestCase):
    def test_every_product_fixture_decodes_with_the_python_consumer(self) -> None:
        cases = {
            "dry-run.ndjson": (False, True, True, 0),
            "failed.ndjson": (False, False, False, 1),
            "partial.ndjson": (False, True, False, 23),
            "refused.ndjson": (True, False, False, 25),
            "success.ndjson": (False, True, False, 0),
        }
        self.assertEqual(
            {path.name for path in FIXTURES.glob("*.ndjson")},
            set(cases),
            "classify every committed automation-v1 fixture",
        )

        for name, (prune, mapping, dry_run, returncode) in cases.items():
            with self.subTest(fixture=name):
                decoder = AutomationDecoder(
                    prune=prune,
                    mapping=mapping,
                    dry_run=dry_run,
                )
                events = [
                    event
                    for line in (FIXTURES / name).read_bytes().splitlines()
                    if (event := decoder.feed(line)) is not None
                ]
                result = decoder.finish(returncode)
                self.assertIsInstance(events[0], syq.RunEvent)
                self.assertIs(events[-1], result)
                self.assertIsInstance(result, syq.CpResult)
                if dry_run:
                    self.assertEqual(result.bytes_transferred, 8)

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
