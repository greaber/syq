from __future__ import annotations

import json
import unittest
from pathlib import Path

import syq
from syq.protocol import AutomationDecoder


class ProgressTests(unittest.TestCase):
    def test_unchanged_schema2_stream_without_estimates(self):
        # Captured from da467d29 before the optional estimate fields were added.
        fixture = Path(__file__).parent / "fixtures/automation-v2-progress.ndjson"
        decoder = AutomationDecoder(prune=False, mapping=False, dry_run=False)
        events = [decoder.feed(line) for line in fixture.read_bytes().splitlines()]
        progress = [event for event in events if isinstance(event, syq.ProgressEvent)]
        self.assertTrue(progress)
        self.assertTrue(all(event.rate_bytes_per_second is None and event.eta_ms is None
                            for event in progress))
        self.assertEqual(str(decoder.finish(0).status), "success")

    def decode(self, **estimates):
        root = Path(__file__).resolve().parents[3]
        run = (root / "tests/fixtures/automation/success.ndjson").read_bytes().splitlines()[0]
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        decoder.feed(run)
        record = {"schema": "syq.automation", "schema_version": 2, "seq": 1,
                  "type": "progress", "bytes_done": 2, "bytes_total": 4,
                  "bytes_unchanged": 0, "files_done": 0, "files_total": 1,
                  "files_unchanged": 0, "files_excluded": 0, "scanned": 1,
                  "scan_done": True, "elapsed_ms": 1000, **estimates}
        return decoder.feed(json.dumps(record).encode())

    def test_optional_progress_estimates(self):
        old = self.decode()
        self.assertIsNone(old.rate_bytes_per_second)
        self.assertIsNone(old.eta_ms)
        current = self.decode(rate_bytes_per_second=2, eta_ms=1000)
        self.assertEqual(current.rate_bytes_per_second, 2)
        self.assertEqual(current.eta_ms, 1000)
        self.assertEqual(self.decode(rate_bytes_per_second=0, eta_ms=0).eta_ms, 0)
        for field in ("rate_bytes_per_second", "eta_ms"):
            for value in (-1, True, 1.5, "2", None, 2**64):
                with self.subTest(field=field, value=value), self.assertRaises(syq.SyqProtocolError):
                    self.decode(**{field: value})
