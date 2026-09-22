#!/usr/bin/env python3
"""Release binary reuse must be exact, complete, and publication-gated."""
import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import textwrap
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("builds", Path(__file__).with_name("find-release-build.py"))
builds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builds)


class Tests(unittest.TestCase):
    assets = builds.ASSETS
    options = []

    def run_record(self, **changes):
        return dict(id=123, head_sha="abc", event="workflow_dispatch",
                    head_branch="master", path=builds.WORKFLOW,
                    head_repository={"full_name": "owner/repo"},
                    status="completed", conclusion="success") | changes

    def select(self, runs, artifacts=None, refreshed=None, watch_status=0):
        def api(path):
            if "artifacts?" in path:
                return {"artifacts": artifacts if artifacts is not None else [
                    {"name": name, "expired": False} for name in self.assets]}
            if "/runs?" in path:
                return {"workflow_runs": runs}
            return refreshed
        output = io.StringIO()
        with patch.object(builds, "api", side_effect=api), patch.object(
                builds.sys, "argv", ["script", "owner/repo", "abc", *self.options]), patch.object(
                builds.subprocess, "run") as watch, contextlib.redirect_stdout(output):
            def finish_watch(command, **kwargs):
                if watch_status and kwargs["check"]:
                    raise builds.subprocess.CalledProcessError(watch_status, command)
                return builds.subprocess.CompletedProcess(command, watch_status)
            watch.side_effect = finish_watch
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
        artifacts = [{"name": name, "expired": False} for name in self.assets]
        for invalid in (*[artifacts[:i] + artifacts[i + 1:] for i in range(len(artifacts))],
                        artifacts + artifacts[:1],
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
        self.assertFalse(watch.call_args.kwargs["check"])
        self.assertEqual(watch.call_args.kwargs["timeout"], 4500)

    def test_candidate_failing_during_wait_falls_back(self):
        output, watch = self.select(
            [self.run_record(status="in_progress", conclusion=None)],
            refreshed=self.run_record(conclusion="failure"), watch_status=1)
        self.assertEqual(output, "")
        watch.assert_called_once()

    def test_interrupted_wait_does_not_start_duplicate_build(self):
        with self.assertRaisesRegex(RuntimeError, "before completion"):
            self.select([self.run_record(status="in_progress", conclusion=None)],
                        refreshed=self.run_record(status="in_progress", conclusion=None),
                        watch_status=1)

    def test_empty(self):
        self.assertEqual(self.select([])[0], "")

    def test_publication_requires_verification_and_either_build_path(self):
        workflow = Path(__file__).resolve().parent.parent / ".github/workflows/release.yml"
        text = workflow.read_text()
        release = text.split("  release:\n", 1)[1]
        for condition in ("needs.verify-tag.result == 'success'",
                          "needs.candidate-build.result == 'success'",
                          "needs.build.result == 'success'",
                          "needs.build.result == 'skipped' && needs.candidate-build.outputs.run-id != ''"):
            self.assertIn(condition, release)
        self.assertIn("run-id: ${{ needs.candidate-build.outputs.run-id || github.run_id }}", release)
        self.assertEqual(release.count(
            "run-id: ${{ needs.candidate-build.outputs.run-id || github.run_id }}"), 2)
        self.assertNotIn("  source-crate:", text)
        build = workflow.with_name("reproducible-builds.yml").read_text()
        crate = build.split("  source-crate:\n", 1)[1].split("  build:\n", 1)[0]
        self.assertNotIn("    needs:", crate)
        self.assertIn('scripts/prepare-release-crate.sh "v$version"', crate)
        self.assertIn('name: source-crate', crate)
        self.assertIn('scripts/verify-prepared-crate.sh "$GITHUB_REF_NAME"', release)



class PythonTests(Tests):
    assets = {f"python-sdk-{target}" for target in (
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin", "aarch64-apple-darwin")}
    options = ["--python-version", "0.7.0"]

    def run_record(self, **changes):
        return super().run_record(**({
            "head_branch": "automation/python-sdk-v0.7.0",
            "path": ".github/workflows/publish-sdks.yml"} | changes))

    def test_shared_tag_gate_rejects_package_version_mismatch(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/publish-sdks.yml").read_text()
        gate = workflow.split("  verify-tag:\n", 1)[1].split("  candidate-python:\n", 1)[0]
        step = gate.split("      - name: Require Python tag version to match package\n", 1)[1]
        self.assertIn("if: startsWith(github.ref, 'refs/tags/sdk-python-v')", step)
        command = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "sdk/python/pyproject.toml"
            package.parent.mkdir(parents=True)
            package.write_text('[project]\nversion = "0.7.0"\n')
            for tag, expected in (("sdk-python-v0.7.0", 0), ("sdk-python-v0.8.0", 1)):
                with self.subTest(tag=tag):
                    result = subprocess.run(
                        ["bash", "-e", "-c", command], cwd=directory,
                        env=dict(os.environ, GITHUB_REF_NAME=tag),
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_master_candidate(self):
        self.assertEqual(self.select([self.run_record(head_branch="master")])[0],
                         "run-id=123\n")

    def test_other_version_or_native_workflow_rejected(self):
        for changes in ({"head_branch": "automation/python-sdk-v0.6.0"},
                        {"path": builds.WORKFLOW}):
            self.assertEqual(self.select([self.run_record(**changes)])[0], "")

    def test_native_artifacts_are_not_python_distributions(self):
        self.assertEqual(self.select([self.run_record()], [
            {"name": name, "expired": False} for name in builds.ASSETS])[0], "")

    def test_publication_requires_verification_and_either_build_path(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/publish-sdks.yml").read_text()
        publish = workflow.split("  publish-python:\n", 1)[1].split("  build-js:", 1)[0]
        for condition in ("needs.verify-tag.result == 'success'",
                          "needs.candidate-python.result == 'success'",
                          "needs.build-python.result == 'success'",
                          "needs.build-python.result == 'skipped' && needs.candidate-python.outputs.run-id != ''",
                          "run-id: ${{ needs.candidate-python.outputs.run-id || github.run_id }}"):
            self.assertIn(condition, publish)
        self.assertIn('test "$GITHUB_SHA" = "$CANDIDATE_COMMIT"', workflow)
        prepare = (root / ".github/workflows/prepare-python-sdk.yml").read_text()
        self.assertLess(prepare.index("gh workflow run publish-sdks.yml"),
                        prepare.index("scripts/run-generated-sdk-post-merge-ci.sh"))
        self.assertLess(prepare.index("scripts/run-generated-sdk-post-merge-ci.sh"),
                        prepare.index("python3 scripts/find-release-build.py"))
        self.assertLess(prepare.index("python3 scripts/find-release-build.py"),
                        prepare.index('git push origin --delete "$branch"'))


if __name__ == "__main__":
    unittest.main()
