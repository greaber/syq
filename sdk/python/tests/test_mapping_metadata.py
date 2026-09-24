from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import syq
from syq.models import _mapping_json
from syq.protocol import AutomationDecoder, parse_mapping_line


class MetadataTests(unittest.TestCase):
    def test_mapping_roundtrip_and_legacy_information(self):
        metadata = syq.DestinationMetadata(mode=0o640, mtime=-1, mtime_nsec=123)
        entry = syq.MappingEntry(b"source-\xff", "out", metadata=metadata, mtime=0, size=0)
        self.assertEqual(parse_mapping_line(json.dumps(_mapping_json(entry)).encode()), entry)
        legacy = parse_mapping_line(json.dumps(_mapping_json(syq.MappingEntry("a", "b", mtime=1))).encode())
        self.assertIsNone(legacy.metadata)
        self.assertEqual(legacy.mtime, 1)
        for invalid in ({"mode": 0o100644}, {"mode": True}, {"uid": 2**32 - 1},
                        {"mtime_nsec": 0}, {"mtime": 1, "mtime_nsec": 10**9}):
            with self.subTest(invalid=invalid), self.assertRaises((TypeError, ValueError)):
                syq.DestinationMetadata(**invalid)
        with self.assertRaisesRegex(ValueError, "symlink"):
            syq.MappingEntry("a", "b", "symlink", metadata=metadata)

    def test_s3_timestamp_is_independent_and_roundtrips(self):
        entry = syq.MappingEntry("a", "b", mtime=123, s3_last_modified=456)
        self.assertEqual(parse_mapping_line(json.dumps(_mapping_json(entry)).encode()), entry)
        self.assertNotIn("mtime", _mapping_json(syq.MappingEntry("a", "b", s3_last_modified=456)))
        self.assertEqual(set(_mapping_json(syq.MappingEntry("a", "b"))), {"src", "dst"})
        with self.assertRaises(TypeError):
            syq.MappingEntry("a", "b", s3_last_modified=True)

    def test_failed_operation_retry_keeps_metadata(self):
        fixture = Path(__file__).resolve().parents[3] / "tests/fixtures/automation/partial.ndjson"
        records = [json.loads(line) for line in fixture.read_bytes().splitlines()]
        for record in records:
            if record["type"] == "operation_result" and record["disposition"] == "failed":
                record["metadata"] = {"mode": 0o600, "mtime": 123}
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        events = [decoder.feed(json.dumps(record).encode()) for record in records]
        decoder.finish(23)
        failed = next(e for e in events if isinstance(e, syq.OperationResult) and e.metadata)
        self.assertEqual(failed.retry_entry().metadata, failed.metadata)
        self.assertEqual(_mapping_json(failed.retry_entry())["metadata"], {"mode": 0o600, "mtime": 123})

    @unittest.skipUnless(os.environ.get("SYQ_CANDIDATE_EXECUTABLE"), "candidate binary required")
    def test_copy_sets_destination_without_changing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            (root / "src/source").write_bytes(b"payload")
            original = (root / "src/source").stat()
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            result = client.cp(mapping=[syq.MappingEntry("source", "result",
                metadata=syq.DestinationMetadata(mode=0o640, mtime=123))], cwd="src", into="out")
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual((root / "out/result").read_bytes(), b"payload")
            self.assertEqual((root / "out/result").stat().st_mtime_ns, 123_000_000_000)
            self.assertEqual((root / "out/result").stat().st_mode & 0o7777, 0o640)
            self.assertEqual((root / "src/source").stat().st_mtime_ns, original.st_mtime_ns)
