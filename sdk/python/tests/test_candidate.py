from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import syq


EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")
EXPECTED_VERSION = os.environ.get("SYQ_CANDIDATE_VERSION")


@unittest.skipUnless(
    EXECUTABLE and EXPECTED_VERSION,
    "candidate compatibility requires SYQ_CANDIDATE_EXECUTABLE and version",
)
class CandidateCompatibilityTests(unittest.TestCase):
    def test_candidate_version_and_typed_native_surface(self) -> None:
        assert EXECUTABLE is not None
        assert EXPECTED_VERSION is not None
        executable = Path(EXECUTABLE)
        self.assertEqual(syq.version(executable=executable), EXPECTED_VERSION)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source; $(not-a-command)"
            destination = root / "destination"
            source.write_bytes(b"candidate compatibility\n")

            client = syq.Client(executable=executable, process_cwd=root)
            events: list[syq.AutomationEvent] = []
            preview = client.cp(
                source.name,
                as_new=destination.name,
                dry_run=True,
                on_event=events.append,
            )
            self.assertTrue(preview.dry_run)
            self.assertEqual(preview.files_planned, 1)
            self.assertEqual(preview.files_completed, 0)
            self.assertFalse(destination.exists())
            self.assertTrue(
                any(
                    isinstance(event, syq.OperationResult)
                    and event.disposition is syq.Disposition.PLANNED
                    for event in events
                )
            )

            result = client.cp(source.name, as_new=destination.name)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.files_completed, 1)
            self.assertEqual(destination.read_bytes(), source.read_bytes())

            mapping_source = root / "mapping-source"
            mapping_source.mkdir()
            (mapping_source / "mapped.txt").write_bytes(b"mapped")
            mapping_alias = root / "mapping-source-link"
            mapping_alias.symlink_to(mapping_source, target_is_directory=True)
            with client.map(src_src=mapping_alias.name, follow=True) as mapping:
                entries = list(mapping)
            self.assertEqual(entries[0].src, syq.RelativePath("mapped.txt"))
            mapped = client.cp(
                mapping=entries,
                cwd=mapping.cwd,
                follow=True,
                into="mapped",
            )
            self.assertEqual(mapped.files_completed, 1)
            self.assertEqual((root / "mapped" / "mapped.txt").read_bytes(), b"mapped")

            prune_source = root / "prune-source"
            prune_target = root / "prune-target"
            prune_source.mkdir()
            prune_target.mkdir()
            (prune_source / "keep").write_bytes(b"keep")
            (prune_target / "extra").write_bytes(b"extra")
            pruned = client.cp_prune(
                src_src=prune_source.name,
                into_existing=prune_target.name,
                max_delete=1,
            )
            self.assertEqual(pruned.deletions_completed, 1)
            self.assertFalse((prune_target / "extra").exists())

            removal_preview = client.rm(destination.name, dry_run=True)
            self.assertEqual(removal_preview.deletions_planned, 1)
            self.assertTrue(destination.exists())
            removed = client.rm(destination.name)
            self.assertEqual(removed.deletions_completed, 1)
            self.assertFalse(destination.exists())

            raw_name = b"raw-\xff"
            raw_source = os.fsencode(root) + b"/" + raw_name
            descriptor = os.open(raw_source, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, b"raw")
            finally:
                os.close(descriptor)
            raw_events: list[syq.AutomationEvent] = []
            raw_result = client.cp(
                src=raw_name,
                into=b"raw-target",
                on_event=raw_events.append,
            )
            self.assertEqual(raw_result.files_completed, 1)
            raw_operation = next(
                event
                for event in raw_events
                if isinstance(event, syq.OperationResult) and event.kind == "file"
            )
            self.assertEqual(raw_operation.dst.raw, raw_name)

    def test_candidate_failure_is_retained(self) -> None:
        assert EXECUTABLE is not None
        result = syq.run(
            ["not-a-syq-command"],
            executable=EXECUTABLE,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
