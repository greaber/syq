from __future__ import annotations

import json
import unittest
from pathlib import Path

import syq
from syq.protocol import AutomationDecoder


class ProgressTests(unittest.TestCase):
    def test_unchanged_schema2_stream_is_explicitly_rejected(self):
        # Unmodified pre-cleanup baseline; the new names require schema 4.
        fixture = Path(__file__).parent / "fixtures/automation-v2-progress.ndjson"
        decoder = AutomationDecoder(prune=False, mapping=False, dry_run=False)
        with self.assertRaisesRegex(syq.SyqProtocolError, "version"):
            decoder.feed(fixture.read_bytes().splitlines()[0])

    def decode(self, **fields):
        root = Path(__file__).resolve().parents[3]
        run = (root / "tests/fixtures/automation/success.ndjson").read_bytes().splitlines()[0]
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        decoder.feed(run)
        record = {"schema": "syq.automation", "schema_version": 4, "seq": 1,
                  "type": "progress", "bytes_done": 2, "bytes_total": 4,
                  "bytes_unchanged": 0, "files_done": 0, "files_total": 1,
                  "files_unchanged": 0, "files_excluded": 0, "scanned": 1,
                  "scan_done": True, "timings": {"total_ms": 1000}, **fields}
        return decoder.feed(json.dumps(record).encode())

    def test_optional_progress_estimates(self):
        current = self.decode(rate_bytes_per_second=2, eta_ms=1000)
        self.assertEqual(current.rate_bytes_per_second, 2)
        self.assertEqual(current.eta_ms, 1000)
        self.assertIsNone(self.decode().eta_ms)
        self.assertEqual(self.decode(rate_bytes_per_second=0, eta_ms=0).eta_ms, 0)
        for field in ("rate_bytes_per_second", "eta_ms"):
            for value in (-1, True, 1.5, "2", None, 2**64):
                with self.subTest(field=field, value=value), self.assertRaises(syq.SyqProtocolError):
                    self.decode(**{field: value})

    def test_measurements_distinguish_zero_from_unavailable_and_allow_overlap(self):
        self.assertIsNone(self.decode().timings.setup_ms)
        timings = dict(total_ms=1000, setup_ms=700, planning_ms=600, transfer_ms=400,
                       finalization_ms=0, helper_install_ms=300)
        current = self.decode(timings=timings)
        self.assertEqual(current.timings, syq.Timings(**timings))
        for field in timings:
            for value in (-1, True, 1.5, "2", None, 2**64):
                with self.subTest(field=field, value=value), self.assertRaises(syq.SyqProtocolError):
                    self.decode(timings={**timings, field: value})
        for value in (None, [], {}, {"setup_ms": 1}):
            with self.assertRaises(syq.SyqProtocolError):
                self.decode(timings=value)

    def test_terminal_timings_are_typed(self):
        root = Path(__file__).resolve().parents[3]
        fixture = root / "tests/fixtures/automation/success.ndjson"
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        for line in fixture.read_bytes().splitlines():
            decoder.feed(line)
        self.assertEqual(decoder.finish(0).timings, syq.Timings(0, 0, 0, 0, 0, 0))
