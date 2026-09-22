#!/usr/bin/env python3
"""Release binary reuse must be exact, complete, and publication-gated."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("builds", Path(__file__).with_name("find-release-build.py"))
builds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builds)


class Tests(unittest.TestCase):
    def run_record(self, **changes):
        return dict(id=123, head_sha="abc", event="workflow_dispatch",
                    head_branch="master", path=builds.WORKFLOW,
                    head_repository={"full_name": "owner/repo"},
                    status="completed", conclusion="success") | changes

    def select(self, runs, artifacts=None, refreshed=None):
        def api(path):
            if "artifacts?" in path:
                return {"artifacts": artifacts if artifacts is not None else [
                    {"name": name, "expired": False} for name in builds.ASSETS]}
            if "/runs?" in path:
                return {"workflow_runs": runs}
            return refreshed
        output = io.StringIO()
        with patch.object(builds, "api", side_effect=api), patch.object(
                builds.sys, "argv", ["script", "owner/repo", "abc"]), patch.object(
                builds.subprocess, "run") as watch, contextlib.redirect_stdout(output):
            builds.main()
        return output.getvalue(), watch

    def test_exact_success(self):
        self.assertEqual(self.select([self.run_record()])[0], "run-id=123\n")

    def test_untrusted_or_other_inputs(self):
        for change in ({"head_sha": "other"}, {"event": "pull_request"},
                       {"head_branch": "other"}, {"path": "other.yml"},
                       {"head_repository": {"full_name": "fork/repo"}}):
            with self.subTest(change=change):
                self.assertEqual(self.select([self.run_record(**change)])[0], "")

    def test_missing_expired_and_duplicate_artifacts(self):
        artifacts = [{"name": name, "expired": False} for name in builds.ASSETS]
        for invalid in (artifacts[:-1], artifacts + artifacts[:1],
                        [item | {"expired": True} for item in artifacts]):
            self.assertEqual(self.select([self.run_record()], invalid)[0], "")

    def test_latest_failure_does_not_reuse_older_success(self):
        self.assertEqual(self.select([self.run_record(), self.run_record(
            id=124, conclusion="failure")])[0], "")

    def test_running_candidate_is_waited_for(self):
        output, watch = self.select([self.run_record(status="in_progress", conclusion=None)],
                                    refreshed=self.run_record())
        self.assertEqual(output, "run-id=123\n")
        watch.assert_called_once()
        self.assertTrue(watch.call_args.kwargs["check"])
        self.assertEqual(watch.call_args.kwargs["timeout"], 4500)

    def test_empty(self):
        self.assertEqual(self.select([])[0], "")

    def test_publication_requires_verification_and_either_build_path(self):
        workflow = Path(__file__).resolve().parent.parent / ".github/workflows/release.yml"
        text = workflow.read_text()
        release = text.split("  release:\n", 1)[1]
        for condition in ("needs.verify-tag.result == 'success'",
                          "needs.candidate-build.result == 'success'",
                          "needs.source-crate.result == 'success'",
                          "needs.build.result == 'success'",
                          "needs.build.result == 'skipped' && needs.candidate-build.outputs.run-id != ''"):
            self.assertIn(condition, release)
        self.assertIn("run-id: ${{ needs.candidate-build.outputs.run-id || github.run_id }}", release)


if __name__ == "__main__":
    unittest.main()
