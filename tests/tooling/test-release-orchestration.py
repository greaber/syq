#!/usr/bin/env python3
"""Fixture-driven checks for path selection, preflight, and release status reporting.

Every GitHub, registry, and remote-Git response comes from fakes; nothing here
creates a tag, a publication, or a CI run.
"""
from support import ROOT, SCRIPTS
import release_checks

import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCOPE_KEYS = ["native", "python_sdk", "tooling", "shellcheck", "mapping_docs",
              "conformance", "macos", "macos_lint", "linux_arm64", "full_suite"]
ALL_TOOLING = "benchmark branch focused installer orchestration package release setup workflows"
# Scope fixtures below supply their own events and overrides.
INHERITED = ("SYQ_TEST_CHANGED_PATHS_FILE", "SYQ_CI_SCOPE_COMMIT", "SYQ_CI_DOCUMENTATION_ONLY",
             "SYQ_CI_SUITES", "GITHUB_REF", "GITHUB_EVENT_NAME", "SYQ_CI_COMPLETE")
BASE_ENV = {key: value for key, value in os.environ.items() if key not in INHERITED}
DISPATCH_EVENT = {}


def parse(output):
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def write_executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class Scratch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-release-orchestration-test.")
        self.work = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def git(self, repo, *args, env=None):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                       env=env or BASE_ENV).strip()

    def init_repo(self, repo):
        repo.mkdir(parents=True, exist_ok=True)
        self.git(repo, "init", "-b", "master", "-q")
        self.git(repo, "config", "user.name", "Test")
        self.git(repo, "config", "user.email", "test@example.com")
        self.git(repo, "config", "commit.gpgsign", "false")

    def event(self, name, value):
        path = self.work / name
        path.write_text(json.dumps(value))
        return path

    def scope(self, *paths, event=None, cwd=None, env=None, macos=False):
        """Run ci-scope on changed paths (or an event) and return its key=value output."""
        run_env = dict(BASE_ENV, **(env or {}))
        args = [str(SCRIPTS / "ci-scope.py")] + (["--macos"] if macos else [])
        if event is None:
            changed = self.work / "paths"
            changed.write_text("".join(path + "\n" for path in paths))
            run_env["SYQ_TEST_CHANGED_PATHS_FILE"] = str(changed)
        else:
            args.append(str(event))
        result = subprocess.run(args, cwd=cwd, env=run_env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return parse(result.stdout)

    def assertScope(self, scope, expected=None, **values):
        for key in expected or {}:
            self.assertEqual(scope[key], expected[key], key)
        for key, value in values.items():
            self.assertEqual(scope[key], value, key)

    def assertAll(self, scope, keys, value):
        for key in keys:
            self.assertEqual(scope[key], value, key)


class WorkflowTextTests(unittest.TestCase):
    def test_macos_workflow_uses_the_scope_it_computes(self):
        # ci-scope.py decides when macOS runs release tooling; the step must run
        # those same groups and pass the inputs ci-scope reads.
        workflow = (ROOT / ".github/workflows/macos.yml").read_text()
        spec = importlib.util.spec_from_file_location("ci_scope", SCRIPTS / "ci-scope.py")
        ci_scope = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci_scope)
        step = workflow.split("      - name: Release tooling suites\n", 1)[1].split("\n      - ", 1)[0]
        groups = step.split("scripts/run-tooling-tests.py --group ", 1)[1].split(" ||", 1)[0]
        self.assertEqual(set(groups.split()), ci_scope.MACOS_TOOLING)
        self.assertIn('scripts/ci-scope.py --macos "$GITHUB_EVENT_PATH"', workflow)
        self.assertIn("SYQ_CI_COMPLETE: ${{ inputs.complete }}", workflow)
        for output in ("needed", "sdk", "release_tooling"):
            self.assertIn(f"{output}: ${{{{ steps.changes.outputs.macos_{output} }}}}", workflow)

    def test_real_ssh_dependency_key_follows_only_the_dependency_stage(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Key the lab's dependency build\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - ", 1)[0])
        dockerfile = (ROOT / "tests/real-ssh/Dockerfile").read_text()
        final = dockerfile.index("\nFROM debian:")
        dependencies = dockerfile.index("\nRUN mkdir src")
        edits = {"final": dockerfile[:final] + "\n# edit" + dockerfile[final:],
                 "dependencies": dockerfile[:dependencies] + "\n# edit" + dockerfile[dependencies:]}

        def key(text, lock="lock\n"):
            with tempfile.TemporaryDirectory(prefix="syq-real-ssh-key-") as temporary:
                root = Path(temporary)
                (root / "tests/real-ssh").mkdir(parents=True)
                (root / "tests/real-ssh/Dockerfile").write_text(text)
                for name, content in [("Cargo.toml", "toml\n"), ("Cargo.lock", lock),
                                      ("build.rs", "build\n")]:
                    (root / name).write_text(content)
                output = root / "output"
                env = dict(BASE_ENV, RUNNER_OS="Linux", RUNNER_ARCH="X64",
                           GITHUB_OUTPUT=str(output))
                if shutil.which("sha256sum") is None:
                    # The step runs on Linux; macOS lacks GNU sha256sum.
                    tools = root / "tools"
                    tools.mkdir()
                    write_executable(tools / "sha256sum", textwrap.dedent(f"""\
                        #!{sys.executable}
                        import hashlib, sys
                        print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + "  -")
                        """))
                    env["PATH"] = f"{tools}{os.pathsep}{env['PATH']}"
                subprocess.run(["bash", "-c", script], cwd=root, check=True, timeout=10, env=env)
                return parse(output.read_text())["key"]

        original = key(dockerfile)
        self.assertRegex(original, r"^real-ssh-dependencies-Linux-X64-[0-9a-f]{64}$")
        self.assertEqual(key(edits["final"]), original)
        self.assertNotEqual(key(edits["dependencies"]), original)
        self.assertNotEqual(key(dockerfile, lock="other\n"), original)

    def test_release_workflow_requires_checks_and_notes(self):
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn(",".join(release_checks.REQUIRED_CHECKS), release)
        # verify-tag is the workflow's only check that the notes exist.
        verify_tag = release.split("\n  verify-tag:\n", 1)[1]
        verify_tag = verify_tag.split("\n  candidate-build:\n", 1)[0]
        self.assertIn('test -s ".github/release-notes/$GITHUB_REF_NAME.md"', verify_tag)


class PathScopeTests(Scratch):
    """Select affected checks; native changes keep broader cross-subsystem,
    architecture, and platform coverage after merge."""

    def test_documentation_and_agent_guidance_select_nothing(self):
        for path in ["README.md", "sdk/README.md", "sdk/RELEASING.md",
                     "sdk/python/README-PYTHON.md", "sdk/python/NATIVE_API.md",
                     "sdk/python/API_DESIGN.md", "book.toml", "theme/head.hbs", "theme/docs.css",
                     "theme/copy-demo.js", ".agents/skills/syq-release/SKILL.md",
                     ".agents/skills/syq-release/agents/openai.yaml"]:
            with self.subTest(path=path):
                self.assertAll(self.scope(path), SCOPE_KEYS, "false")

    def test_sdk_inputs_and_native_api(self):
        # Documentation exceptions must not hide SDK fixtures, build metadata, or
        # the API specification consumed by the native CLI.
        for path in ["sdk/python/tests/example.md", "sdk/python/pyproject.toml"]:
            with self.subTest(path=path):
                self.assertScope(self.scope(path), python_sdk="true")
        self.assertScope(self.scope("docs/mappings.md"), mapping_docs="true", native="false")
        self.assertScope(self.scope("sdk/python/src/syq/syq-release-manifest.json"),
                         native="false", python_sdk="true")
        self.assertScope(self.scope("sdk/python/native-api.json"),
                         native="true", python_sdk="true")

    def test_new_tooling_tests_do_not_select_product_suites(self):
        self.assertScope(self.scope("tests/tooling/test-new.py"), tooling="true",
                         native="false", python_sdk="false", conformance="false")

    def test_python_sdk_tooling(self):
        for path in ["nix/python-dist.nix", "scripts/build-python-dist.sh",
                     "scripts/package-python-wheel.py", "scripts/pin-python-native-source.py",
                     "scripts/normalize-python-wheel.py", "scripts/check-python-api-sync.py",
                     "scripts/normalize-python-sdist.py", "scripts/check-python-wheel.py",
                     "scripts/stage-python-sdk.py", "scripts/prepare-python-sdk-release.py",
                     "scripts/run-generated-sdk-post-merge-ci.py", "scripts/select-trusted-pr.jq",
                     "tests/tooling/test-python-sdk-release-tools.py",
                     "scripts/verify-python-release-preparation.py"]:
            with self.subTest(path=path):
                self.assertScope(self.scope(path), tooling="true", python_sdk="true",
                                 native="false")

    def test_single_path_classification(self):
        self.assertScope(self.scope("tests/rsync-compat/LEDGER.md"),
                         conformance="true", native="false")
        self.assertScope(self.scope("src/main.rs"), native="true", python_sdk="false",
                         conformance="false", macos="false", linux_arm64="false")
        # The macOS cross-target lint accompanies every Rust selection and its own
        # script, without promoting either to the other.
        for path in ["src/main.rs", "Cargo.lock", "build.rs", "tests/local/transfer.rs"]:
            with self.subTest(path=path):
                self.assertScope(self.scope(path), native="true", macos_lint="true")
        self.assertScope(self.scope("scripts/check-macos-lint.py"), macos_lint="true",
                         native="false", tooling="true")
        self.assertScope(self.scope(".github/workflows/ci.yml"), macos_lint="false")
        for path in ["docs/example.sh", "tests/real-ssh/scenarios.sh"]:
            with self.subTest(path=path):
                self.assertScope(self.scope(path), shellcheck="true", tooling="false",
                                 native="false")
        self.assertScope(self.scope("tests/tooling/test-installer.py"), tooling="true", native="false")
        scope = self.scope(".github/workflows/ci.yml")
        self.assertScope(scope, tooling="true")
        self.assertAll(scope, ["native", "python_sdk", "shellcheck", "mapping_docs",
                               "conformance", "macos", "linux_arm64", "full_suite"], "false")
        self.assertScope(self.scope(".github/workflows/rsync-compat.yml"), tooling="true",
                         conformance="false", native="false")
        self.assertScope(self.scope(".github/workflows/pages.yml"), tooling="true",
                         python_sdk="false", native="false")

    def test_pinned_tools_run_everything_that_uses_them(self):
        scope = self.scope("scripts/setup.lock")
        self.assertAll(scope, ["native", "python_sdk", "tooling", "shellcheck",
                               "mapping_docs", "conformance"], "true")
        self.assertScope(scope, tooling_checks=ALL_TOOLING)
        self.assertAll(scope, ["macos", "linux_arm64", "full_suite"], "false")

    def test_test_runner_config_selects_native_platform_and_setup_tests(self):
        scope = self.scope(".config/nextest.toml")
        self.assertScope(scope, native="true", macos="true", tooling="true",
                         tooling_checks="setup")
        self.assertAll(scope, ["python_sdk", "conformance"], "false")

    def test_pull_request_190_surface(self):
        # The surface touched by PR #190 should run the Rust baseline, Python SDK, and
        # shell lint without promoting the pull request to unrelated suites.
        scope = self.scope("docs/copy-files.md", "sdk/python/native-api.json",
                           "sdk/python/src/syq/client.py", "src/cli.rs", "tests/local.rs",
                           "tests/real-ssh/scenarios.sh")
        self.assertScope(scope, native="true", python_sdk="true", shellcheck="true")
        self.assertAll(scope, ["tooling", "mapping_docs", "conformance", "macos", "linux_arm64",
                               "full_suite"], "false")

    def test_integration_targets(self):
        self.assertScope(self.scope("tests/local/transfer.rs"), integration_targets="local")
        self.assertScope(self.scope("tests/support/temp.rs"), integration_targets="all")
        self.assertScope(self.scope("tests/tls.rs"), integration_targets="tls")

    def test_tooling_changes_select_their_own_suites(self):
        # Tooling changes select their own suites, without product builds. Any
        # script change also checks the script references in workflows and docs.
        for path, checks in [("tests/tooling/test-release-tools.py", "release workflows"),
                             ("tests/tooling/test-installer.py", "installer workflows"),
                             ("tests/tooling/test-try-benchmark.py", "benchmark workflows"),
                             ("scripts/benchmark-concurrency.py", "benchmark workflows"),
                             ("tests/tooling/test-benchmark-concurrency.py", "benchmark workflows"),
                             ("tests/tooling/test-run-focused-check.py", "focused workflows"),
                             ("tests/tooling/test-branch-status.py", "branch workflows"),
                             ("scripts/setup.sh", "setup workflows"),
                             ("tests/tooling/test-setup.sh", "setup workflows"),
                             ("tests/tooling/test-rust-test-timeouts.py", "setup workflows"),
                             ("tests/tooling/test-release-orchestration.py",
                              "orchestration workflows"),
                             ("scripts/check-macos-lint.py", "orchestration workflows"),
                             ("scripts/release_checks.py", "orchestration release workflows"),
                             ("scripts/verify-release-ci.py",
                              "orchestration release workflows"),
                             (".github/workflows/macos.yml", "orchestration workflows"),
                             (".github/workflows/ci.yml", "orchestration workflows"),
                             (".github/actionlint.yaml", "orchestration workflows"),
                             ("scripts/check-script-references.py",
                              "orchestration workflows")]:
            with self.subTest(path=path):
                scope = self.scope(path)
                self.assertScope(scope, tooling_checks=checks)
                self.assertAll(scope, ["native", "python_sdk", "conformance", "macos"], "false")
        self.assertScope(self.scope("scripts/rsync-compat.py"), conformance="true",
                         tooling_checks="workflows")
        scope = self.scope("tests/tooling/test-installer.py", "tests/tooling/test-release-tools.py",
                           "tests/tooling/test-installer.py")
        self.assertScope(scope, tooling_checks="installer release workflows")
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        self.assertScope(self.scope(event=dispatch), tooling_checks=(
            "package installer benchmark release orchestration focused branch workflows setup"))
        reverse = self.scope("tests/tooling/test-release-tools.py", "tests/tooling/test-installer.py")
        self.assertScope(reverse, tooling_checks="installer release workflows")
        self.assertScope(self.scope("build.rs"), tooling_checks="package", native="true")

    def test_mapped_path_never_suppresses_fallback(self):
        # A mapped path must never suppress another path's broad tooling fallback.
        for fallback in ["nix/python-dist.nix", "unknown-input", "scripts/unmapped-tool.py"]:
            for mapped in [".github/workflows/ci.yml", "tests/tooling/test-installer.py"]:
                for paths in ([fallback], [fallback, mapped], [mapped, fallback]):
                    with self.subTest(paths=paths):
                        scope = self.scope(*paths)
                        self.assertScope(scope, tooling="true", tooling_checks=ALL_TOOLING)


class EventScopeTests(Scratch):
    """Scope real task branch, push, and dispatch events in a scratch repository."""

    @classmethod
    def setUpClass(cls):
        cls.repo_temp = tempfile.TemporaryDirectory(prefix="syq-scope-repo.")
        repo = cls.repo = Path(cls.repo_temp.name) / "scope-repo"
        helper = Scratch()
        git = helper.git
        helper.init_repo(repo)
        (repo / "README.md").write_text("documentation\n")
        (repo / "MAPPINGS.md").write_text("mapping\n")
        git(repo, "add", "README.md", "MAPPINGS.md")
        git(repo, "commit", "-qm", "base")
        cls.base = git(repo, "rev-parse", "HEAD")
        (repo / "sdk/python").mkdir(parents=True)
        (repo / "sdk/python/mapping").write_text("mapping\n")
        git(repo, "add", "sdk/python/mapping")
        git(repo, "commit", "-qm", "sdk")
        cls.head = git(repo, "rev-parse", "HEAD")
        # A pull request branch may lag master.
        git(repo, "switch", "-qc", "docs", cls.base)
        with (repo / "README.md").open("a") as readme:
            readme.write("more documentation\n")
        git(repo, "commit", "-qam", "docs")
        cls.docs_head = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "-q", "master")
        (repo / "src").mkdir()
        (repo / "src/main.rs").write_text("fn main() {}\n")
        git(repo, "add", "src/main.rs")
        git(repo, "commit", "-qm", "native")
        cls.advanced_base = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "-qc", "rename", cls.base)
        (repo / "docs").mkdir()
        git(repo, "mv", "MAPPINGS.md", "docs/mappings.md")
        git(repo, "commit", "-qm", "rename")
        cls.rename_head = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "-qc", "documentation-push", cls.advanced_base)
        (repo / "docs").mkdir(exist_ok=True)
        (repo / "theme").mkdir(exist_ok=True)
        (repo / "docs/mappings.md").write_text("mapping examples\n")
        (repo / "sdk/python/NATIVE_API.md").write_text("API guide\n")
        (repo / "theme/docs.css").write_text("body {}\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "documentation-push")
        cls.documentation_head = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "-qc", "sdk-doc-rename", cls.advanced_base)
        git(repo, "mv", "sdk/python/mapping", "sdk/python/NATIVE_API.md")
        git(repo, "commit", "-qm", "sdk-doc-rename")
        cls.sdk_rename_head = git(repo, "rev-parse", "HEAD")
        # Generated Python SDK validation passes an exact checked-out commit.
        (repo / "sdk/python/syq-release-manifest.json").write_text("release manifest\n")
        git(repo, "add", "sdk/python/syq-release-manifest.json")
        git(repo, "commit", "-qm", "generated-python-sdk")
        cls.scoped_dispatch_head = git(repo, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls):
        cls.repo_temp.cleanup()

    def branch_scope(self, base, head):
        """Scope a manual macOS run on a task branch at `head` with origin/master at `base`."""
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        tree = self.work / "branch"
        self.git(self.repo, "update-ref", "refs/remotes/origin/master", base)
        try:
            self.git(self.repo, "worktree", "add", "-q", "--detach", str(tree), head)
            return self.scope(event=dispatch, cwd=tree, macos=True,
                              env={"GITHUB_EVENT_NAME": "workflow_dispatch",
                                   "GITHUB_REF": "refs/heads/task"})
        finally:
            self.git(self.repo, "worktree", "remove", "--force", str(tree))
            self.git(self.repo, "update-ref", "-d", "refs/remotes/origin/master")

    def push(self, before, after):
        return self.event("push-event.json", {"before": before, "after": after})

    def test_task_branch_scopes_its_own_diff(self):
        scope = self.branch_scope(self.base, self.head)
        self.assertScope(scope, native="false", python_sdk="true", full_suite="false")
        # Scope the branch's own three-dot diff rather than treating unrelated
        # base-branch changes as part of the branch.
        scope = self.branch_scope(self.advanced_base, self.docs_head)
        self.assertAll(scope, SCOPE_KEYS, "false")

    def test_rename_exposes_both_sides(self):
        # Rename detection must expose both the affected source and inert destination.
        scope = self.branch_scope(self.advanced_base, self.rename_head)
        self.assertScope(scope, mapping_docs="true", native="false", python_sdk="false")
        # Both sides of a rename remain visible even when the destination is one of
        # the explicitly excluded SDK documents.
        scope = self.scope(event=self.push(self.advanced_base, self.sdk_rename_head),
                           cwd=self.repo)
        self.assertScope(scope, python_sdk="true")

    def test_push_scopes(self):
        scope = self.scope(event=self.push(self.head, self.advanced_base), cwd=self.repo)
        self.assertScope(scope, native="true")
        self.assertAll(scope, ["python_sdk", "conformance", "macos", "linux_arm64",
                               "full_suite"], "false")
        # Reproduce a documentation-only post-merge push, including the SDK guide and
        # executable mapping examples. Only the focused example checks are selected.
        scope = self.scope(event=self.push(self.advanced_base, self.documentation_head),
                           cwd=self.repo)
        for key in SCOPE_KEYS:
            self.assertEqual(scope[key], "true" if key == "mapping_docs" else "false", key)

    def test_workflow_dispatch(self):
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        self.assertAll(self.scope(event=dispatch, cwd=self.repo), SCOPE_KEYS, "true")
        # Generated Python SDK validation passes an exact checked-out commit, retaining
        # normal path selection instead of treating its workflow dispatch as a manual
        # full-suite request.
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env={"SYQ_CI_SCOPE_COMMIT": self.scoped_dispatch_head})
        self.assertScope(scope, native="false", python_sdk="true")
        self.assertAll(scope, ["tooling", "shellcheck", "mapping_docs", "conformance", "macos",
                               "linux_arm64", "full_suite"], "false")
        result = subprocess.run(
            [str(SCRIPTS / "ci-scope.py"), str(dispatch)], cwd=self.repo, capture_output=True,
            text=True, env=dict(BASE_ENV,
                                SYQ_CI_SCOPE_COMMIT="0123456789abcdef0123456789abcdef01234567"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not checked out", result.stdout + result.stderr)

    def test_selected_suites(self):
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        branch = {"GITHUB_REF": "refs/heads/task"}
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env=dict(branch, SYQ_CI_SUITES="real-ssh-max-sessions-1, s3 real-ssh-core"))
        self.assertScope(scope, suite_selection="true", s3="true", native="false",
                         repository_checks="false", full_suite="false")
        # Matrix order is fixed so equal selections share cancellation groups.
        self.assertEqual(json.loads(scope["real_ssh_matrix"]),
                         [{"suite": "core", "profile": "default"},
                          {"suite": "core", "profile": "max-sessions-1",
                           "skip": "tests/real-ssh/max-sessions-1.skip"}])
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env=dict(branch, SYQ_CI_SUITES="rust real-ssh macos-intel"))
        self.assertScope(scope, native="true", integration_targets="all", macos="true",
                         macos_intel="true", s3="false", tooling="false", full_suite="false")
        self.assertEqual(len(json.loads(scope["real_ssh_matrix"])), 3)
        # On task branches the rust job's name records what it ran.
        self.assertScope(scope, rust_label="native:all", all_tooling="false", macos_lint="false")
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env=dict(branch, SYQ_CI_SUITES="macos-lint"))
        self.assertScope(scope, macos_lint="true", native="false", tooling="false",
                         rust_label="none", real_ssh_matrix="[]", full_suite="false")
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env=dict(branch, SYQ_CI_SUITES="shellcheck tooling"))
        self.assertScope(scope, rust_label="tooling:all shellcheck", all_tooling="true",
                         native="false")
        self.assertScope(self.scope(event=dispatch, cwd=self.repo,
                                    env=dict(branch, SYQ_CI_DOCUMENTATION_ONLY="true")),
                         rust_label="mapping-docs")
        scope = self.scope(event=dispatch, cwd=self.repo,
                           env=dict(branch, SYQ_CI_SUITES="quick"))
        self.assertScope(scope, rust_label="tooling:quick", quick_tooling="true", tooling="true",
                         tooling_checks="", all_tooling="false", native="false",
                         shellcheck="false", conformance="false", full_suite="false",
                         s3="false", python_sdk="false", mapping_docs="false")
        for names in ("quick tooling", "tooling quick"):
            scope = self.scope(event=dispatch, cwd=self.repo,
                               env=dict(branch, SYQ_CI_SUITES=names))
            self.assertScope(scope, rust_label="tooling:all", quick_tooling="true",
                             all_tooling="true",
                             native="false", full_suite="false")
            self.assertEqual(set(scope["tooling_checks"].split()), set(ALL_TOOLING.split()))
        # Path classification and full runs never select suites.
        self.assertScope(self.scope("src/main.rs"), suite_selection="false", s3="false",
                         real_ssh_matrix="[]", rust_label="native:bin", all_tooling="false")
        self.assertScope(self.scope(event=dispatch, cwd=self.repo), suite_selection="false",
                         s3="true", repository_checks="true", macos_intel="true",
                         all_tooling="true", rust_label="full")
        for env, message in [
                (dict(branch, SYQ_CI_SUITES="s3 bogus"), "unknown suite: bogus"),
                ({"GITHUB_REF": "refs/heads/master", "SYQ_CI_SUITES": "s3"}, "not master"),
                (dict(branch, SYQ_CI_SUITES="s3", SYQ_CI_DOCUMENTATION_ONLY="true"),
                 "cannot be combined")]:
            with self.subTest(env=env):
                result = subprocess.run([str(SCRIPTS / "ci-scope.py"), str(dispatch)],
                                        cwd=self.repo, capture_output=True, text=True,
                                        env=dict(BASE_ENV, **env))
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)
                self.assertEqual(result.stdout, "")

    def macos_scope(self, event, *paths, ref="refs/heads/master", event_name="push",
                    complete="", cwd=ROOT):
        env = dict(GITHUB_EVENT_NAME=event_name, GITHUB_REF=ref, SYQ_CI_COMPLETE=complete)
        scope = self.scope(*paths, event=None if paths else event, cwd=cwd, env=env, macos=True)
        return scope["macos_needed"], scope["macos_sdk"], scope["macos_release_tooling"]

    def test_macos_classification_step(self):
        push = self.push(self.head, self.advanced_base)
        for expected, paths in [
                (("false", "false", "false"), ["docs/mappings.md", "sdk/python/NATIVE_API.md"]),
                (("false", "false", "false"), ["theme/docs.js", "book.toml"]),
                (("false", "false", "false"), ["tests/real-ssh/scenarios.sh", "docs/example.sh"]),
                (("false", "false", "false"), ["docs/mappings.md", "src/main.rs"]),
                (("false", "true", "false"), ["sdk/python/native-api.json"]),
                (("false", "true", "false"), ["sdk/python/src/syq/client.py"]),
                (("false", "false", "true"), ["tests/tooling/test-installer.py"]),
                (("false", "false", "true"), [".github/workflows/macos.yml"]),
                (("true", "false", "false"), ["src/tune/network/macos.rs"]),
                (("true", "true", "true"), ["src/tune/network/macos.rs", "scripts/setup.lock"]),
                (("true", "false", "false"), ["tests/macos_exfat.rs"]),
                (("false", "true", "true"), ["unknown-input"])]:
            with self.subTest(paths=paths):
                self.assertEqual(self.macos_scope(push, *paths), expected)
        # A manual release-validation run on master starts every step.
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        self.assertEqual(self.macos_scope(dispatch, event_name="workflow_dispatch"),
                         ("true", "true", "true"))

    def test_macos_task_branch_runs_scope_its_own_changes(self):
        dispatch = self.event("workflow-dispatch-event.json", DISPATCH_EVENT)
        self.git(self.repo, "update-ref", "refs/remotes/origin/master", self.base)
        tree = self.work / "task"
        try:
            self.git(self.repo, "worktree", "add", "-q", "--detach", str(tree), self.docs_head)
            run = lambda **options: self.macos_scope(
                dispatch, event_name="workflow_dispatch", ref="refs/heads/task", cwd=tree,
                **options)
            # A manual run always starts the suite, without unrelated steps.
            self.assertEqual(run(), ("true", "false", "false"))
            self.assertEqual(run(complete="true"), ("true", "true", "true"))
            self.git(tree, "checkout", "-q", "--detach", self.head)
            self.assertEqual(run(), ("true", "true", "false"))
            (tree / "scripts").mkdir()
            (tree / "scripts/release-preflight.py").write_text("release\n")
            self.git(tree, "add", "scripts/release-preflight.py")
            self.git(tree, "commit", "-qm", "release tooling")
            self.assertEqual(run(), ("true", "true", "true"))
        finally:
            self.git(self.repo, "worktree", "remove", "--force", str(tree))
            self.git(self.repo, "update-ref", "-d", "refs/remotes/origin/master")


class NestedSuiteTests(unittest.TestCase):
    def run_suite(self, name, **env):
        subprocess.run([sys.executable, str(Path(__file__).with_name(name))], env=dict(BASE_ENV, **env), check=True)

    def test_release_test_inputs_under_the_nightly_environment(self):
        # Exercise the nested fixtures under the environment that exposed the leak.
        # No GitHub token should be needed: all API interactions are fixture-owned.
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory, "nightly-event.json")
            event.write_text('{"schedule":"17 2 * * *"}\n')
            self.run_suite("test-release-test-inputs.py", GITHUB_EVENT_PATH=str(event),
                           GITHUB_EVENT_NAME="schedule", GITHUB_REPOSITORY="example/repo",
                           GITHUB_REF_NAME="master",
                           GITHUB_WORKFLOW_REF="example/repo/.github/workflows/ci.yml@refs/heads/master")

    def test_nightly_ignores_inherited_overrides(self):
        self.run_suite("test-nightly-ci.py", SYQ_TEST_CHANGED_PATHS_FILE="/nonexistent-inherited-path",
                       SYQ_CI_SCOPE_COMMIT="invalid", SYQ_CI_DOCUMENTATION_ONLY="true", FAIL_API="1")


FAKE_PREFLIGHT_GIT = """#!/bin/sh
if [ "$1" = ls-remote ]; then
  case " $* " in
    *' refs/heads/master '*) printf '%s\\trefs/heads/master\\n' "$SYQ_TEST_PREFLIGHT_HEAD" ;;
  esac
  exit 0
fi
exec "$SYQ_TEST_REAL_GIT" "$@"
"""

FAKE_PREFLIGHT_GH = """#!{python}
import json, os, sys
args = sys.argv[1:]
if args[:2] == ["api", "--paginate"]:
    args = ["api"] + args[3:]
env = os.environ
key = ":".join((args + ["", ""])[:2])
joined = " " + " ".join(args) + " "
def fail():
    print("unexpected fake gh invocation: " + " ".join(args), file=sys.stderr)
    sys.exit(2)
if key == "repo:view":
    print("greaber/syq")
elif key == "secret:list":
    print(json.dumps([{{"name": "SYQ_RELEASE_SIGNING_KEY_PEM_B64"}}, {{"name": "HOMEBREW_TAP_DEPLOY_KEY"}}]))
elif key == "variable:list":
    key_value = env.get("SYQ_TEST_PUBLIC_KEY") or "A" * 43 + "="
    print(json.dumps([{{"name": "SYQ_RELEASE_PUBLIC_KEY", "value": key_value}}]))
elif key == "api:user":
    print("greaber")
elif args[:1] == ["api"]:
    if "/commits/" in joined and "/check-runs" in joined.split("/commits/", 1)[1]:
        print(env["SYQ_TEST_CHECKS_JSON"])
    elif "/attempts/" in joined and "/jobs?" in joined.split("/attempts/", 1)[1]:
        print('[{{"jobs":[{{"name":"release-certification","status":"completed","conclusion":"success"}}]}}]')
    elif "/actions/workflows/" in joined and "/runs?" in joined.split("/actions/workflows/", 1)[1]:
        print("[" + env["SYQ_TEST_WORKFLOW_RUNS_JSON"] + "]")
    elif "/actions/permissions/selected-actions " in joined:
        print(env["SYQ_TEST_SELECTED_ACTIONS_JSON"])
    elif "/actions/permissions " in joined:
        print('{{"enabled":true,"allowed_actions":"selected","sha_pinning_required":true}}')
    elif "/deployment-branch-policies " in joined:
        print('{{"branch_policies":[{{"name":"v*","type":"tag"}}]}}')
    elif "/environments/release " in joined:
        print('{{"name":"release","protection_rules":[{{"type":"required_reviewers"}}]}}')
    elif "users/greaber/ssh_signing_keys" in joined:
        print(json.dumps([{{"key": env["SYQ_TEST_SIGNING_KEY"]}}]))
    elif "/releases?per_page=100 " in joined:
        print("[[]]")
    elif "homebrew-tap/contents/Formula/syq.rb " in joined:
        print(json.dumps({{"content": env["SYQ_TEST_FORMULA_B64"]}}))
    else:
        fail()
else:
    fail()
"""

FAKE_PREFLIGHT_CURL = """#!{python}
import json, os
version = os.environ.get("SYQ_TEST_EXISTING_CRATE_VERSION", "")
print(json.dumps({{"versions": [{{"num": version}}] if version else []}}))
"""


def check_runs(*names):
    return json.dumps({"check_runs": [{"name": name, "conclusion": "success"} for name in names]})


def pinned_signing_key():
    for line in (SCRIPTS / "release-tag-signers").read_text().splitlines():
        fields = line.split()
        if fields and fields[0] == "syq-release":
            for index in range(1, len(fields) - 1):
                if fields[index].startswith("ssh-"):
                    return f"{fields[index]} {fields[index + 1]}"
    raise AssertionError("release-tag-signers has no syq-release key")


class PreflightTests(Scratch):
    """Build a clean disposable canonical checkout and serve every GitHub/registry
    response from fixtures. The preflight must not create a tag or publication."""

    def setUp(self):
        super().setUp()
        repo = self.repo = self.work / "preflight-repo"
        bin_dir = self.work / "preflight-bin"
        for directory in [".github/release-notes", ".github/workflows", "scripts", "sdk/python", "src"]:
            (repo / directory).mkdir(parents=True)
        bin_dir.mkdir()
        shutil.copy(SCRIPTS / "check-python-api-sync.py", repo / "scripts")
        (repo / "src/release-public-key.txt").write_text("A" * 43 + "=\n")
        (repo / "sdk/python/native-api.json").write_text('{"schema":1,"commands":{}}\n')
        (repo / "Cargo.toml").write_text('[package]\nname = "syq"\nversion = "9.9.9"\n')
        (repo / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "syq"\nversion = "9.9.9"\n')
        (repo / ".github/workflows/release.yml").write_text(
            "steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "  - uses: rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9\n")
        (repo / ".github/release-notes/v9.9.9.md").write_text("Release fixture notes\n")
        self.init_repo(repo)
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-qm", "initial")
        self.git(repo, "remote", "add", "origin", "git@github.com:greaber/syq.git")
        self.head = self.git(repo, "rev-parse", "HEAD")
        self.tree = self.git(repo, "rev-parse", "HEAD^{tree}")
        self.receipt = repo / f".git/syq-release/real-ssh/{self.tree}.json"
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_text(json.dumps({"schema": 1, "commit": self.head, "tree": self.tree,
                                            "profile": "default", "result": "success"}))
        self.git(repo, "update-ref", "refs/remotes/origin/master", self.head)
        self.signing_key = pinned_signing_key()
        self.git(repo, "config", "gpg.format", "ssh")
        self.git(repo, "config", "user.signingkey", "key::" + self.signing_key)
        self.git(repo, "config", "tag.gpgsign", "true")
        write_executable(bin_dir / "git", FAKE_PREFLIGHT_GIT)
        write_executable(bin_dir / "gh", FAKE_PREFLIGHT_GH.format(python=sys.executable))
        write_executable(bin_dir / "curl", FAKE_PREFLIGHT_CURL.format(python=sys.executable))
        self.workflow_runs = {"workflow_runs": [{
            "head_branch": "master", "head_repository": {"full_name": "greaber/syq"}, "id": 601,
            "event": "workflow_dispatch", "head_sha": self.head, "status": "completed",
            "conclusion": "success", "run_number": 1, "run_attempt": 1}]}
        formula = 'url "https://github.com/greaber/syq/releases/download/v9.9.8/syq"\n'
        self.env = dict(
            BASE_ENV,
            SYQ_TEST_PREFLIGHT_HEAD=self.head,
            SYQ_TEST_REAL_GIT=shutil.which("git"),
            SYQ_TEST_CHECKS_JSON=check_runs("rust", "sdks", "macos", "linux-arm64", "conformance"),
            SYQ_TEST_WORKFLOW_RUNS_JSON=json.dumps(self.workflow_runs),
            SYQ_TEST_SELECTED_ACTIONS_JSON=json.dumps({
                "github_owned_allowed": True, "verified_allowed": False,
                "patterns_allowed": [
                    "rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9"]}),
            SYQ_TEST_SIGNING_KEY=self.signing_key,
            SYQ_TEST_FORMULA_B64=base64.b64encode(formula.encode()).decode(),
            PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])

    def tool(self, script, *args, **env):
        return subprocess.run([str(script), *args], cwd=self.repo, env=dict(self.env, **env),
                              capture_output=True, text=True)

    def preflight(self, script=SCRIPTS / "release-preflight.py", **env):
        return self.tool(script, "v9.9.9", **env)

    def assertPasses(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assertFails(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stdout + result.stderr)

    def readiness(self, **env):
        result = self.tool(SCRIPTS / "release-readiness.py", "v9.9.9", "--json", **env)
        return result.returncode, json.loads(result.stdout)

    def later_master(self):
        self.git(self.repo, "switch", "-qc", "later-master")
        (self.repo / "later-source").write_text("new development work\n")
        self.git(self.repo, "add", "later-source")
        self.git(self.repo, "commit", "-qm", "later")
        later = self.git(self.repo, "rev-parse", "HEAD")
        self.git(self.repo, "switch", "--detach", "-q", self.head)
        return later

    def test_candidate_passes(self):
        result = self.preflight()
        self.assertPasses(result)
        self.assertIn(f"Release preflight passed for v9.9.9 at {self.head}", result.stdout)
        # Scheduled full certificates satisfy the same release gate as manual runs.
        nightly = json.loads(json.dumps(self.workflow_runs))
        nightly["workflow_runs"][0]["event"] = "schedule"
        self.assertPasses(self.tool(SCRIPTS / "verify-release-ci.py", "greaber/syq", self.head,
                                    SYQ_TEST_WORKFLOW_RUNS_JSON=json.dumps(nightly)))

    def test_rotated_repository_key_must_update_source_key(self):
        # Rotating the repository key must also update the embedded source-build key.
        self.assertFails(self.preflight(SYQ_TEST_PUBLIC_KEY="B" * 43 + "="),
                         "SYQ_RELEASE_PUBLIC_KEY differs from src/release-public-key.txt")

    def test_allowlist_options_do_not_move_the_pinned_key(self):
        # Exercise preflight with allowlist options whose quoted whitespace changes
        # field positions. Keep the repository's real allowlist untouched.
        option_scripts = self.work / "tag-option-scripts"
        option_scripts.mkdir()
        shutil.copy(SCRIPTS / "release-preflight.py", option_scripts)
        for name in ["release_checks.py", "verify-release-ci.py", "release_test_inputs.py",
                     "tooling.py"]:
            (option_scripts / name).symlink_to(SCRIPTS / name)
        for options in ["", 'namespaces="git"', 'namespaces="git, file",valid-before="20990101"']:
            with self.subTest(options=options):
                (option_scripts / "release-tag-signers").write_text(
                    f"syq-release {options} {self.signing_key}\n")
                self.assertPasses(self.preflight(option_scripts / "release-preflight.py"))

    def test_other_registered_signing_key_is_rejected(self):
        key = self.work / "other-preflight-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        other = " ".join(Path(f"{key}.pub").read_text().split()[:2])
        self.git(self.repo, "config", "user.signingkey", "key::" + other)
        self.assertFails(self.preflight(SYQ_TEST_SIGNING_KEY=other), "not the pinned maintainer key")

    def test_missing_evidence_or_existing_publication_is_rejected(self):
        for env, message in [
                ({"SYQ_TEST_CHECKS_JSON": check_runs("rust", "sdks", "macos", "linux-arm64")},
                 "required check conformance is missing"),
                ({"SYQ_TEST_WORKFLOW_RUNS_JSON": '{"workflow_runs":[]}'},
                 "has no push, schedule, or workflow_dispatch run on master"),
                ({"SYQ_TEST_EXISTING_CRATE_VERSION": "9.9.9"}, "already published on crates.io")]:
            with self.subTest(message=message):
                self.assertFails(self.preflight(**env), message)
        # Readiness reports the same missing named check that preflight rejects.
        status, report = self.readiness(
            SYQ_TEST_CHECKS_JSON=check_runs("rust", "sdks", "macos", "linux-arm64"))
        self.assertEqual(status, 1, report)
        self.assertEqual([item["message"] for item in report["missing"]],
                         [f"required check conformance is missing on certified commit {self.head}"])

    def test_api_follow_ups_are_read_from_the_checked_repository(self):
        # The candidate's own inventory decides, not that of the scripts' checkout.
        (self.repo / "sdk/python/native-api.json").write_text(
            '{"schema":1,"commands":{"copy":{"sdk":"supported","follow_up":["example"]}}}\n')
        self.git(self.repo, "commit", "-qam", "pending follow-up")
        candidate = self.git(self.repo, "rev-parse", "HEAD")
        self.git(self.repo, "update-ref", "refs/remotes/origin/master", candidate)
        env = {"SYQ_TEST_PREFLIGHT_HEAD": candidate}
        self.assertFails(self.preflight(**env), "syq copy: Python SDK follow-up required")
        status, report = self.readiness(**env)
        self.assertEqual(status, 1, report)
        self.assertTrue(any("Python native API synchronization failed" in item["message"]
                            for item in report["missing"]))

    def test_branch_names_do_not_define_the_candidate(self):
        # Branch names and the coordination branch tip do not define the candidate.
        self.git(self.repo, "switch", "-qc", "release-task")
        self.assertPasses(self.preflight())
        self.git(self.repo, "switch", "--detach", "-q")
        self.assertPasses(self.preflight())
        status, report = self.readiness()
        self.assertEqual(status, 0, report)
        self.assertTrue(report["ready"])
        self.assertEqual(len(report["ci"]["workflows"]), 3)
        self.assertEqual(report["ssh"]["profile"], "default")

    def test_pinned_candidate_survives_master_advance(self):
        # A pinned, validated candidate remains releasable after master advances.
        later = self.later_master()
        self.git(self.repo, "update-ref", "refs/remotes/origin/master", later)
        self.assertPasses(self.preflight(SYQ_TEST_PREFLIGHT_HEAD=later))
        status, report = self.readiness(SYQ_TEST_PREFLIGHT_HEAD=later)
        self.assertEqual(status, 0, report)
        self.assertTrue(report["ready"])
        self.assertEqual(report["commit"], self.head)
        self.assertEqual(report["remote_master"], later)

    def test_unrelated_candidate_is_rejected_by_both_entry_points(self):
        unrelated = self.git(self.repo, "commit-tree", self.tree, "-m", "unrelated")
        self.git(self.repo, "update-ref", "refs/remotes/origin/master", unrelated)
        self.assertFails(self.preflight(SYQ_TEST_PREFLIGHT_HEAD=unrelated),
                         "not merged into remote master")
        status, report = self.readiness(SYQ_TEST_PREFLIGHT_HEAD=unrelated)
        self.assertNotEqual(status, 0)
        self.assertFalse(report["ready"])
        self.assertTrue(any("not merged into remote master" in item["message"]
                            for item in report["missing"]))

    def test_stale_ref_dirty_tree_and_missing_ssh_evidence(self):
        # Stale tracking refs still require a fetch, without moving the candidate.
        later = self.later_master()
        self.assertFails(self.preflight(SYQ_TEST_PREFLIGHT_HEAD=later), "origin/master is stale")
        (self.repo / "untracked").write_text("uncommitted")
        self.assertFails(self.preflight(), "working tree is not clean")
        # A configuration that hides untracked files does not hide them here.
        self.git(self.repo, "config", "status.showUntrackedFiles", "no")
        self.assertFails(self.preflight(), "working tree is not clean")
        (self.repo / "untracked").unlink()
        self.receipt.unlink()
        self.assertFails(self.preflight(), "real-SSH evidence is missing")

    def test_existing_release_resumes_without_receipts_or_ci(self):
        # Existing releases resume immediately, even without local SSH receipts or CI.
        self.receipt.unlink()
        self.git(self.repo, "-c", "tag.gpgsign=false", "tag", "v9.9.9")
        status, report = self.readiness(SYQ_TEST_WORKFLOW_RUNS_JSON='{"workflow_runs":[]}')
        self.assertEqual(status, 1)
        self.assertIsNone(report["ci"])
        self.assertEqual(report["next_action"], "scripts/release-status.py v9.9.9")

    def test_macos_lint_runs_first_until_the_macos_suite_certifies(self):
        # A copy of readiness beside a fake lint; the real one would build syq.
        scripts = self.work / "lint-scripts"
        scripts.mkdir()
        shutil.copy(SCRIPTS / "release-readiness.py", scripts)
        for name in ["release_checks.py", "verify-release-ci.py", "release_test_inputs.py",
                     "tooling.py", "check-python-api-sync.py"]:
            (scripts / name).symlink_to(SCRIPTS / name)
        marker = self.work / "lint-ran"
        write_executable(scripts / "check-macos-lint.py", textwrap.dedent(f"""\
            #!{sys.executable}
            import os, pathlib, sys
            pathlib.Path({str(marker)!r}).write_text(os.getcwd())
            print("fake lint output")
            sys.exit(int(os.environ["SYQ_TEST_LINT_STATUS"]))
            """))
        def readiness(lint_status, **env):
            marker.unlink(missing_ok=True)
            result = self.tool(scripts / "release-readiness.py", "v9.9.9", "--json",
                               SYQ_TEST_LINT_STATUS=str(lint_status), **env)
            return result.returncode, json.loads(result.stdout), result.stderr

        # A certified macOS suite already covers the lint.
        status, report, _ = readiness(1)
        self.assertEqual(status, 0, report)
        self.assertEqual(report["macos_lint"], "skipped")
        self.assertFalse(marker.exists())

        # Without that certificate, a lint failure comes before the SSH lab and CI,
        # and its output stays off the JSON report.
        self.receipt.unlink()
        uncertified = {"SYQ_TEST_WORKFLOW_RUNS_JSON": '{"workflow_runs":[]}'}
        status, report, stderr = readiness(1, **uncertified)
        self.assertEqual(status, 1)
        self.assertTrue(os.path.samefile(marker.read_text(), self.repo))
        self.assertIn("fake lint output", stderr)
        self.assertEqual(report["macos_lint"], "failed")
        self.assertIn("macOS lint failed", report["missing"][0]["message"])
        self.assertIn("scripts/check-macos-lint.py", report["next_action"])
        self.assertIn("--check-ssh", report["missing"][1]["next_action"])

        status, report, _ = readiness(0, **uncertified)
        self.assertEqual(report["macos_lint"], "passed")
        self.assertFalse(any("macOS lint" in item["message"] for item in report["missing"]))
        self.assertIn("--check-ssh", report["next_action"])

        # A lint that cannot run is listed last and never becomes the next action.
        status, report, _ = readiness(2, **uncertified)
        self.assertEqual(report["macos_lint"], "unavailable")
        self.assertIn("could not run", report["missing"][-1]["message"])
        self.assertTrue(any("macos.yml" in item["message"] for item in report["missing"][:-1]))
        self.assertIn("--check-ssh", report["next_action"])


FAKE_STATUS_GH = """#!{python}
import json, os, sys
args = sys.argv[1:]
env = os.environ
key = ":".join((args + ["", ""])[:2])
joined = " " + " ".join(args) + " "
def fail():
    print("unexpected fake gh invocation: " + " ".join(args), file=sys.stderr)
    sys.exit(2)
sha = env.get("SYQ_TEST_STATUS_COMMIT")
tag = env.get("SYQ_TEST_STATUS_TAG")
if key == "run:list":
    runs = []
    if json.loads(env.get("SYQ_TEST_STATUS_INCLUDE_FAILED_RUN") or "false"):
        runs.append({{"conclusion": "failure", "databaseId": 302, "event": "push", "headSha": sha,
                     "status": "completed", "url": "https://example.test/302",
                     "workflowName": "release"}})
    runs.append({{"conclusion": env.get("SYQ_TEST_STATUS_RUN_CONCLUSION") or None,
                 "databaseId": 303, "event": "push", "headSha": sha,
                 "status": env.get("SYQ_TEST_STATUS_RUN_STATUS") or "in_progress",
                 "url": "https://example.test/303", "workflowName": "release"}})
    print(json.dumps(runs))
elif args[:1] == ["api"]:
    if f"/git/matching-refs/tags/{{tag}} " in joined:
        print(json.dumps([{{"ref": "refs/tags/" + tag,
                           "object": {{"type": "tag", "sha": env["SYQ_TEST_STATUS_TAG_OBJECT"]}}}}]))
    elif "/git/tags/" in joined:
        print(json.dumps({{"tag": env.get("SYQ_TEST_STATUS_OBJECT_TAG") or tag,
                          "object": {{"type": env.get("SYQ_TEST_STATUS_TARGET_TYPE") or "commit",
                                     "sha": sha}},
                          "verification": {{"verified": True, "reason": "valid"}}}}))
    elif "/releases?per_page=100 " in joined:
        print(json.dumps([[{{"tag_name": tag, "draft": False, "immutable": True,
                            "html_url": "https://example.test/" + tag}}]]))
    elif "/actions/runs/303/pending_deployments " in joined:
        print('[{{"environment":{{"name":"release"}}}}]')
    elif "homebrew-tap/contents/Formula/syq.rb " in joined:
        print(json.dumps({{"content": env["SYQ_TEST_STATUS_FORMULA_B64"]}}))
    else:
        fail()
else:
    fail()
"""

FAKE_STATUS_CURL = """#!{python}
import json, os, sys
joined = " " + " ".join(sys.argv[1:]) + " "
version = os.environ["SYQ_TEST_STATUS_VERSION"]
if "crates.io/" in joined:
    print(json.dumps({{"versions": [{{"num": version}}]}}))
elif "pypi.org/" in joined:
    print(json.dumps({{"info": {{"version": version}}, "releases": {{version: [{{}}]}}}}))
else:
    sys.exit(2)
"""


class ReleaseStatusTests(Scratch):
    """Release status correlates the exact tag commit with runs, pending protected
    environments, and every publication destination."""

    commit = "89abcdef0123456789abcdef0123456789abcdef"

    def setUp(self):
        super().setUp()
        bin_dir = self.work / "status-bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "gh", FAKE_STATUS_GH.format(python=sys.executable))
        write_executable(bin_dir / "curl", FAKE_STATUS_CURL.format(python=sys.executable))
        manifest = json.loads((ROOT / "sdk/python/src/syq/syq-release-manifest.json").read_text())
        self.tag = manifest["tag"]
        formula = f'url "https://github.com/greaber/syq/releases/download/{self.tag}/syq"\n'
        self.env = dict(
            BASE_ENV, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
            SYQ_TEST_STATUS_COMMIT=self.commit,
            SYQ_TEST_STATUS_TAG_OBJECT="76543210abcdef9876543210abcdef9876543210",
            SYQ_TEST_STATUS_TAG=self.tag, SYQ_TEST_STATUS_VERSION=manifest["version"],
            SYQ_TEST_STATUS_FORMULA_B64=base64.b64encode(formula.encode()).decode())

    def status(self, **env):
        # The PyPI mapping is read from the current checkout, as in CI.
        result = subprocess.run([str(SCRIPTS / "release-status.py"), "--json", self.tag], cwd=ROOT,
                                env=dict(self.env, **env), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_pending_release_run(self):
        status = self.status()
        self.assertEqual(status["tag_state"], "verified", status)
        self.assertEqual(status["tag_commit"], self.commit)
        self.assertEqual(status["github_release"]["state"], "published")
        self.assertIs(status["github_release"]["immutable"], True)
        self.assertEqual(status["release_runs"][0]["databaseId"], 303)
        self.assertEqual(status["release_runs"][0]["pending_environments"], ["release"])
        self.assertIs(status["complete"], False)
        for destination in ["crates_io", "pypi", "homebrew"]:
            self.assertEqual(status["publications"][destination]["state"], "published", destination)

    def test_completed_release(self):
        status = self.status(SYQ_TEST_STATUS_RUN_STATUS="completed",
                             SYQ_TEST_STATUS_RUN_CONCLUSION="success")
        self.assertIs(status["complete"], True)

    def test_failed_attempt_does_not_hide_later_publication(self):
        # A failed provisional attempt does not make a later successful publication
        # incomplete. Keep both runs in the report for auditability.
        status = self.status(SYQ_TEST_STATUS_INCLUDE_FAILED_RUN="true",
                             SYQ_TEST_STATUS_RUN_STATUS="completed",
                             SYQ_TEST_STATUS_RUN_CONCLUSION="success")
        self.assertIs(status["complete"], True)
        conclusions = [run["conclusion"] for run in status["release_runs"]]
        self.assertEqual(conclusions.count("failure"), 1)
        self.assertEqual(conclusions.count("success"), 1)

    def test_mismatched_or_nested_tag_objects(self):
        status = self.status(SYQ_TEST_STATUS_OBJECT_TAG=f"{self.tag}-mismatch")
        self.assertEqual(status["tag_state"], "name-mismatch")
        self.assertIsNone(status["tag_commit"])
        status = self.status(SYQ_TEST_STATUS_TARGET_TYPE="tag")
        self.assertEqual(status["tag_state"], "invalid-target")
        self.assertIsNone(status["tag_commit"])


if __name__ == "__main__":
    unittest.main()
