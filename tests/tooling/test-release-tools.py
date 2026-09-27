#!/usr/bin/env python3
"""Exercise complete release assembly and Ed25519 signing with small stand-in
binaries. Optionally reuse a candidate already built by the caller:
tests/tooling/test-release-tools.py --syq /absolute/path/to/syq
"""
from support import SCRIPTS

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tooling import cargo_version

REPOSITORY = SCRIPTS.parent

VERSION = cargo_version(REPOSITORY / "Cargo.toml")
TAG = f"v{VERSION}"
ASSETS = ["syq-linux-x86_64", "syq-linux-aarch64", "syq-macos-arm64", "syq-macos-x86_64"]
CANONICALIZER = None

COMMIT = "13fc7d1093b28aadd212e1a7ffabcfa277ba3b20"
TAG_SHA = "89abcdef0123456789abcdef0123456789abcdef"
REF_JSON = {"object": {"type": "tag", "sha": TAG_SHA}}
# Unchanged published tag: verification must accept the existing maintainer key.
TAG_JSON = json.loads((REPOSITORY / "tests/fixtures/release-tag-v0.4.1.json").read_text())
COMPARE_JSON = {"base_commit": {"sha": COMMIT}, "merge_base_commit": {"sha": COMMIT}}
CHECKS_JSON = {"check_runs": [
    {"id": 1, "name": "rust", "started_at": "2026-01-01T00:00:00Z", "status": "completed",
     "conclusion": "failure"},
    {"id": 2, "name": "rust", "started_at": "2026-01-01T00:01:00Z", "status": "completed",
     "conclusion": "success"},
    {"name": "macos", "status": "completed", "conclusion": "success"},
    {"name": "verify signed release tag", "status": "in_progress", "conclusion": None}]}
CI_JOBS_JSON = [{"jobs": [{"name": "release-certification", "status": "completed",
                           "conclusion": "success"}]}]


def run_record(**changes):
    return {"head_branch": "master", "head_repository": {"full_name": "greaber/syq"}, "id": 701,
            "event": "workflow_dispatch", "head_sha": COMMIT, "status": "completed",
            "conclusion": "success", "run_number": 1, "run_attempt": 1, **changes}


WORKFLOW_RUNS_JSON = {"workflow_runs": [run_record()]}
FAILED_WORKFLOW_RUNS = {"workflow_runs": [run_record(),
                                          run_record(id=702, conclusion="failure", run_number=2)]}
PUSH_RUNS = {"workflow_runs": [run_record(event="push")]}
PENDING_RUNS = {"workflow_runs": [run_record(event="push", status="in_progress", conclusion=None)]}
NO_RUNS = {"workflow_runs": []}

FAKE_GH = """#!/bin/sh
if [ "$1" = api ] && [ "${2:-}" = --paginate ]; then
  shift 3
  set -- api "$@"
fi
case "$1:$2" in
  api:*/git/ref/tags/*) printf '%s\\n' "$SYQ_TEST_REF_JSON" ;;
  api:*/git/tags/*) printf '%s\\n' "$SYQ_TEST_TAG_JSON" ;;
  api:*/compare/*) printf '%s\\n' "$SYQ_TEST_COMPARE_JSON" ;;
  api:*/check-runs*) printf '%s\\n' "$SYQ_TEST_CHECKS_JSON" ;;
  api:*/attempts/1/jobs?*) printf '%s\\n' "${SYQ_TEST_CI_JOBS_JSON:-}" ;;
  api:*/actions/workflows/macos.yml/runs?*) printf '[%s]\\n' "${SYQ_TEST_MACOS_RUNS_JSON:-$SYQ_TEST_WORKFLOW_RUNS_JSON}" ;;
  api:*/actions/workflows/*/runs?*) printf '[%s]\\n' "$SYQ_TEST_WORKFLOW_RUNS_JSON" ;;
  release:download)
    shift 2
    destination=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --dir) destination=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    cp "$SYQ_TEST_PUBLISHED_DIR/"* "$destination/"
    ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 2 ;;
esac
"""


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def openssl(*args, **kwargs):
    return subprocess.run(["openssl", *args], check=True, stdout=subprocess.PIPE, **kwargs).stdout


def public_key_b64(key):
    der = openssl("pkey", "-in", str(key), "-pubout", "-outform", "DER")
    return openssl("base64", "-A", input=der[-32:]).decode().rstrip("\n")


class ReleaseToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-release-test.")
        self.work = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def prepare_dist(self, name):
        dist = self.work / name
        dist.mkdir()
        for asset in ASSETS:
            binary = dist / asset
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            archive = subprocess.run(["gzip", "-9", "-n", "-c", str(binary)], check=True,
                                     stdout=subprocess.PIPE).stdout
            (dist / f"{asset}.gz").write_bytes(archive)
        return dist

    def package(self, name):
        dist = self.prepare_dist(name)
        subprocess.run([str(SCRIPTS / "package-release.py"), TAG, str(dist)], check=True)
        return dist

    def expect_failure(self, expected, command, env=None):
        result = subprocess.run([str(part) for part in command], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(result.returncode, 0, f"command unexpectedly succeeded: {command}")
        self.assertIn(expected, result.stdout)
        return result

    def fake_env(self, **values):
        fakebin = self.work / "fakebin"
        if not fakebin.exists():
            fakebin.mkdir()
            (fakebin / "gh").write_text(FAKE_GH)
            (fakebin / "gh").chmod(0o755)
        env = dict(os.environ, PATH=f"{fakebin}{os.pathsep}{os.environ['PATH']}",
                   SYQ_TEST_CI_JOBS_JSON=json.dumps(CI_JOBS_JSON))
        for name, value in values.items():
            env[f"SYQ_TEST_{name}"] = value if isinstance(value, str) else json.dumps(value)
        return env

    def verify_ci(self, *arguments, **values):
        return [SCRIPTS / "verify-release-ci.py", *arguments, "greaber/syq", COMMIT], \
            self.fake_env(**values)

    def verify_tag(self, checks="rust,macos", commit=COMMIT, **values):
        values = {"REF_JSON": REF_JSON, "TAG_JSON": TAG_JSON, **values}
        return [SCRIPTS / "verify-release-tag.py", "greaber/syq", "v0.4.1", commit, "master",
                checks], self.fake_env(**values)

    def test_packaging_is_complete_reproducible_and_strict(self):
        first = self.package("first")
        second = self.package("second")
        self.assertEqual(len([path for path in first.iterdir() if path.is_file()]), 19)
        for checksum in ("syq-linux-x86_64.sha256", "syq-linux-x86_64.gz.sha256"):
            digest, name = (first / checksum).read_text().rstrip("\n").split("  ")
            self.assertEqual(digest, sha256(first / name), checksum)
        manifest = json.loads((first / "syq-release-manifest.json").read_text())
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(sorted(manifest), ["artifacts", "homebrew_formula", "installer", "repository",
                                            "schema", "signature_scheme", "tag", "version"])
        self.assertEqual(len(manifest["artifacts"]), 4)
        self.assertEqual(manifest["installer"]["name"], "install.sh")
        self.assertEqual(manifest["installer"]["sha256"], sha256(first / "install.sh"))
        self.assertEqual(manifest["homebrew_formula"]["name"], "syq.rb")
        self.assertEqual(manifest["homebrew_formula"]["sha256"], sha256(first / "syq.rb"))
        self.assertEqual(manifest["signature_scheme"], "ed25519-jcs-v1")
        self.assertNotIn("signature", manifest)
        subprocess.run(["sh", "-n", str(first / "install.sh")], check=True)
        formula = (first / "syq.rb").read_text()
        self.assertIn("class Syq < Formula", formula.split("\n"))
        self.assertIn("https://dl.syq.christmas/v", formula)
        if shutil.which("ruby"):
            subprocess.run(["ruby", "-c", str(first / "syq.rb")], check=True,
                           stdout=subprocess.DEVNULL)

        # Packaging is reproducible byte-for-byte and rejects both partial and
        # contaminated release directories.
        self.assertEqual(sorted(path.name for path in first.iterdir()),
                         sorted(path.name for path in second.iterdir()))
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes(), path.name)
        missing = self.prepare_dist("missing")
        (missing / "syq-macos-arm64.gz").unlink()
        self.expect_failure("missing regular asset",
                            [SCRIPTS / "package-release.py", TAG, missing])
        unexpected = self.prepare_dist("unexpected")
        (unexpected / "extra").write_text("not a release asset\n")
        self.expect_failure("release directory contains missing or unexpected files",
                            [SCRIPTS / "package-release.py", TAG, unexpected])
        self.expect_failure("does not match Cargo.toml version",
                            [SCRIPTS / "package-release.py", "v99.99.99", first])

    def test_crates_io_accepts_only_the_exact_package(self):
        # crates.io reruns accept only the exact package checksum, distinguish a
        # missing version with exit 3, and fail closed on registry errors.
        source_crate = self.work / "syq-0.1.0.crate"
        source_crate.write_text("source crate\n")
        response = self.work / "crate-response.json"
        response.write_text(json.dumps({"version": {"num": "0.1.0", "checksum": sha256(source_crate)}}))
        command = [SCRIPTS / "verify-crates-io-package.py", "0.1.0", source_crate]

        def env(status):
            return dict(os.environ, SYQ_TEST_CRATES_IO_RESPONSE=str(response),
                        SYQ_TEST_CRATES_IO_STATUS=status)

        subprocess.run([str(part) for part in command], env=env("200"), check=True,
                       stdout=subprocess.DEVNULL)
        result = subprocess.run([str(part) for part in command], env=env("404"),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertEqual(result.returncode, 3)
        self.assertIn("is not published on crates.io", result.stdout)
        response.write_text(json.dumps({"version": {"num": "0.1.0", "checksum": "a" * 64}}))
        self.expect_failure("differs from the package assembled from this tag", command, env("200"))
        self.expect_failure("returned HTTP 500", command, env("500"))

    def test_signing_verifies_and_rejects_a_mismatched_key(self):
        # Run the same signing operation used by the release workflow, verify the
        # result independently, and prove that a mismatched configured public key is
        # rejected without modifying the manifest.
        first = self.package("first")
        second = self.package("second")
        key = self.work / "signing.pem"
        public = self.work / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("pkey", "-in", str(key), "-pubout", "-out", str(public))
        key_b64 = openssl("base64", "-A", "-in", str(key)).decode().rstrip("\n")
        # A secret set from a file keeps its trailing newline.
        env = dict(os.environ, SYQ_RELEASE_SIGNING_KEY_PEM_B64=key_b64 + "\n",
                   SYQ_RELEASE_PUBLIC_KEY=public_key_b64(key))
        manifest = first / "syq-release-manifest.json"
        subprocess.run([str(SCRIPTS / "sign-release-manifest.py"), str(manifest), CANONICALIZER],
                       env=env, check=True)
        self.assertEqual(len([path for path in first.iterdir() if path.is_file()]), 19)
        embedded_b64 = json.loads(manifest.read_text())["signature"]
        self.assertTrue(embedded_b64)
        signature = self.work / "embedded-signature.raw"
        signature.write_bytes(openssl("base64", "-d", "-A", input=embedded_b64.encode()))
        payload = self.work / "manifest.jcs"
        payload.write_bytes(subprocess.run(
            [CANONICALIZER, "--release-manifest-signing-payload", str(manifest)], check=True,
            stdout=subprocess.PIPE).stdout)
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-in", str(payload),
                "-sigfile", str(signature))

        other_key = self.work / "other.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other_key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        unsigned = second / "syq-release-manifest.json"
        second_sha = sha256(unsigned)
        self.expect_failure("does not match SYQ_RELEASE_PUBLIC_KEY",
                            [SCRIPTS / "sign-release-manifest.py", unsigned, CANONICALIZER],
                            dict(env, SYQ_RELEASE_PUBLIC_KEY=public_key_b64(other_key)))
        self.assertEqual(sha256(unsigned), second_sha)
        self.assertNotIn("signature", json.loads(unsigned.read_text()))

    def test_verified_tag_and_release_ci_are_accepted(self):
        # Verify the workflow's GitHub tag checks against controlled API responses.
        command, env = self.verify_tag(WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON,
                                       COMPARE_JSON=COMPARE_JSON, CHECKS_JSON=CHECKS_JSON)
        subprocess.run([str(part) for part in command], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        command, env = self.verify_ci(WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON)
        subprocess.run([str(part) for part in command], env=env, check=True,
                       stdout=subprocess.DEVNULL)

    def test_release_ci_requires_trusted_full_certificates(self):
        self.expect_failure("has no push, schedule, or workflow_dispatch run on master",
                            *self.verify_ci(WORKFLOW_RUNS_JSON=NO_RUNS))
        self.expect_failure("is completed/failure", *self.verify_ci(WORKFLOW_RUNS_JSON=FAILED_WORKFLOW_RUNS))
        # Reuse only exact-commit, own-repository master runs with full evidence.
        command, env = self.verify_ci(WORKFLOW_RUNS_JSON=PUSH_RUNS)
        subprocess.run([str(part) for part in command], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        for conclusion in ("skipped", "failure", "cancelled", None):
            with self.subTest(conclusion=conclusion):
                jobs = [{"jobs": [{"name": "release-certification", "status": "completed",
                                   "conclusion": conclusion}]}]
                self.expect_failure("lacks successful full-suite",
                                    *self.verify_ci(CI_JOBS_JSON=jobs, WORKFLOW_RUNS_JSON=PUSH_RUNS))
        self.expect_failure("lacks successful full-suite",
                            *self.verify_ci(CI_JOBS_JSON=[{"jobs": []}], WORKFLOW_RUNS_JSON=PUSH_RUNS))
        for field, value in [("head_sha", "wrong"), ("head_branch", "feature"),
                             ("head_repository", {"full_name": "someone/syq"}),
                             ("event", "pull_request")]:
            with self.subTest(field=field):
                untrusted = {"workflow_runs": [run_record(**{"event": "push", field: value})]}
                self.expect_failure("has no push, schedule, or workflow_dispatch run on master",
                                    *self.verify_ci(WORKFLOW_RUNS_JSON=untrusted))
        self.expect_failure("is in_progress/pending", *self.verify_ci(WORKFLOW_RUNS_JSON=PENDING_RUNS))
        # A retry cannot borrow the first attempt's successful certificate.
        retry = {"workflow_runs": [run_record(event="push", run_attempt=2)]}
        self.expect_failure("/attempts/2/jobs", *self.verify_ci(WORKFLOW_RUNS_JSON=retry))
        self.expect_failure("macos.yml has no push, schedule, or workflow_dispatch run",
                            *self.verify_ci(MACOS_RUNS_JSON=NO_RUNS, WORKFLOW_RUNS_JSON=PUSH_RUNS))

    def test_structured_release_ci_readiness(self):
        # Structured readiness distinguishes waiting, missing evidence, and failures.
        for runs, expected in [(PENDING_RUNS, "wait"), (FAILED_WORKFLOW_RUNS, "repair"),
                               (NO_RUNS, "dispatch"), (PUSH_RUNS, "ready")]:
            with self.subTest(expected=expected):
                command, env = self.verify_ci("--json", WORKFLOW_RUNS_JSON=runs)
                result = subprocess.run([str(part) for part in command], env=env,
                                        stdout=subprocess.PIPE, text=True)
                self.assertEqual(result.returncode, 0 if expected == "ready" else 1)
                workflows = json.loads(result.stdout)["workflows"]
                self.assertEqual(len(workflows), 3)
                self.assertTrue(all(workflow["state"] == expected for workflow in workflows))

    def test_tag_verification_rejects_invalid_tags_and_checks(self):
        lightweight = {"object": {"type": "commit", "sha": COMMIT}}
        self.expect_failure("is lightweight", *self.verify_tag(REF_JSON=lightweight))
        unsigned = {"tag": "v0.4.1", "object": {"type": "commit", "sha": COMMIT},
                    "verification": {"verified": False, "reason": "unsigned"}}
        self.expect_failure("reason: unsigned", *self.verify_tag(TAG_JSON=unsigned))
        self.expect_failure("not workflow commit", *self.verify_tag(commit="a" * 40))
        unmerged = {"base_commit": {"sha": COMMIT}, "merge_base_commit": {"sha": "b" * 40}}
        self.expect_failure("not reachable from protected branch master", *self.verify_tag(
            WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON, COMPARE_JSON=unmerged))
        # A red, pending, or absent required check on the tagged commit blocks the
        # release even when the tag itself is valid and merged.
        failed = {"check_runs": [{"name": "rust", "status": "completed", "conclusion": "failure"},
                                 {"name": "macos", "status": "completed", "conclusion": "success"}]}
        self.expect_failure("required check rust is failure", *self.verify_tag(
            WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON, COMPARE_JSON=COMPARE_JSON, CHECKS_JSON=failed))
        pending = {"check_runs": [{"name": "rust", "status": "in_progress", "conclusion": None},
                                  {"name": "macos", "status": "completed", "conclusion": "success"}]}
        self.expect_failure("required check rust is pending", *self.verify_tag(
            WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON, COMPARE_JSON=COMPARE_JSON, CHECKS_JSON=pending))
        self.expect_failure("required check linux-arm64 is missing", *self.verify_tag(
            checks="rust,macos,linux-arm64", WORKFLOW_RUNS_JSON=WORKFLOW_RUNS_JSON,
            COMPARE_JSON=COMPARE_JSON, CHECKS_JSON=CHECKS_JSON))

    def test_tag_verification_requires_signature_fields(self):
        # Missing and malformed API fields must fail with a useful diagnostic.
        for field in ("signature", "payload"):
            for value in ("missing", None, "", 123):
                with self.subTest(field=field, value=value):
                    invalid = copy.deepcopy(TAG_JSON)
                    if value == "missing":
                        del invalid["verification"][field]
                    else:
                        invalid["verification"][field] = value
                    self.expect_failure(f"missing, empty, or invalid verification {field}",
                                        *self.verify_tag(TAG_JSON=invalid))

    def test_tag_verification_requires_the_pinned_maintainer_key(self):
        # A valid signature by another key is not release authority, even when GitHub
        # reports it as verified. Use an ephemeral test key, never a maintainer secret.
        key = self.work / "other-tag-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        payload = self.work / "other-tag-payload"
        payload.write_text(TAG_JSON["verification"]["payload"])
        # This fixture uses its local private key, never an inherited agent.
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "git", str(payload)],
                       env=dict(os.environ, SSH_AUTH_SOCK=""), check=True)
        other_signer = copy.deepcopy(TAG_JSON)
        other_signer["verification"]["signature"] = Path(f"{payload}.sig").read_text()
        self.expect_failure("not signed by the pinned maintainer key",
                            *self.verify_tag(TAG_JSON=other_signer))
        tampered = copy.deepcopy(TAG_JSON)
        tampered["verification"]["payload"] += "tampered"
        self.expect_failure("not signed by the pinned maintainer key",
                            *self.verify_tag(TAG_JSON=tampered))

    def test_published_assets_must_match_byte_for_byte(self):
        # Published-release reruns compare content, not just asset names.
        local = self.work / "local-assets"
        published = self.work / "published-assets"
        local.mkdir()
        published.mkdir()
        (local / "syq.rb").write_text("formula\n")
        (local / "syq-linux-x86_64").write_text("binary\n")
        for path in local.iterdir():
            shutil.copy(path, published / path.name)
        command = [SCRIPTS / "verify-release-assets.py", "v0.1.0", local]
        env = self.fake_env(PUBLISHED_DIR=str(published))
        subprocess.run([str(part) for part in command], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        (published / "syq.rb").write_text("changed formula\n")
        self.expect_failure("published release asset differs", command, env)
        shutil.copy(local / "syq.rb", published / "syq.rb")
        (published / "syq-linux-x86_64").unlink()
        self.expect_failure("different asset inventory", command, env)


def require_ed25519_openssl():
    # Ed25519 raw signing with pkeyutl needs OpenSSL 3. macOS ships LibreSSL as
    # `openssl`, and OpenSSL 1.1.1 lacks `pkeyutl -rawin`; Homebrew's openssl@3
    # works once its bin directory is first on PATH.
    help_text = subprocess.run(["openssl", "pkeyutl", "-help"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT).stdout
    if b"-rawin" not in help_text:
        found = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        found = found.stdout.rstrip("\n") if found.returncode == 0 else "unknown"
        print(f"{sys.argv[0]} needs OpenSSL 3 for Ed25519 raw signing; found: {found}",
              file=sys.stderr)
        print("on macOS, install openssl@3 with Homebrew and put its bin directory first on PATH",
              file=sys.stderr)
        sys.exit(1)


def main():
    global CANONICALIZER
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--syq":
        if len(arguments) < 2:
            print("usage: tests/tooling/test-release-tools.py [--syq PATH]", file=sys.stderr)
            sys.exit(2)
        CANONICALIZER = arguments[1]
        if not os.path.isfile(CANONICALIZER) or not os.access(CANONICALIZER, os.X_OK):
            print(f"missing executable syq canonicalizer: {CANONICALIZER}", file=sys.stderr)
            sys.exit(1)
        del sys.argv[1:3]
    require_ed25519_openssl()
    if CANONICALIZER is None:
        manifest = str(REPOSITORY / "Cargo.toml")
        subprocess.run(["cargo", "build", "--locked", "--manifest-path", manifest, "--bin", "syq"],
                       check=True)
        metadata = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1",
                                   "--manifest-path", manifest], check=True,
                                  stdout=subprocess.PIPE, text=True).stdout
        CANONICALIZER = os.path.join(json.loads(metadata)["target_directory"], "debug", "syq")
    unittest.main()


if __name__ == "__main__":
    main()
