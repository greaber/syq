#!/usr/bin/env python3
"""Run SYQ against a pinned, classified subset of the upstream rsync suite."""

from __future__ import annotations

import argparse
import collections
import hashlib
from html import escape
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
COMPAT_DIR = ROOT / "tests" / "rsync-compat"
MANIFEST_PATH = COMPAT_DIR / "manifest.toml"
INVENTORY_PATH = COMPAT_DIR / "inventory.tsv"
LEDGER_PATH = COMPAT_DIR / "LEDGER.md"
REGRESSIONS_PATH = COMPAT_DIR / "regressions.toml"
REGRESSIONS_LEDGER_PATH = COMPAT_DIR / "REGRESSIONS.md"
VALID_CLASSES = {"conformance", "adapted", "unsupported", "out-of-scope", "unassessed"}
VALID_OUTCOMES = {"pass", "fail", "skip", "xfail"}
VALID_POSITIONS = {
    "compatible",
    "unimplemented",
    "intentional-divergence",
    "policy-open",
    "test-unresolved",
}
POSITION_LABELS = {
    "compatible": "Compatible",
    "unimplemented": "Unimplemented",
    "intentional-divergence": "Intentional divergence",
    "policy-open": "Policy open",
    "test-unresolved": "Test unresolved",
}
POSITION_DESCRIPTIONS = {
    "compatible": "The exercised behavior currently agrees with the reviewed rsync behavior.",
    "unimplemented": "Relevant behavior that SYQ does not currently implement.",
    "intentional-divergence": "SYQ deliberately uses different behavior for this scenario.",
    "policy-open": "SYQ differs and the desired compatibility policy is not decided.",
    "test-unresolved": "The observation may reflect the fixture, harness, or an unclear test claim.",
}
VALID_ADAPTATION_KINDS = {"invocation", "fixture", "subset"}
VALID_REGRESSION_PRIORITIES = {"critical", "high", "medium", "low"}
VALID_REGRESSION_IMPACTS = {
    "availability",
    "correctness",
    "data-integrity",
    "data-loss",
    "resource-exhaustion",
    "security",
}
VALID_REGRESSION_STATUSES = {"covered", "partial", "candidate", "not-applicable"}
RESULT_RE = re.compile(r"^(PASS|FAIL|SKIP|XFAIL)\s+([^\s(]+)")


class CompatError(RuntimeError):
    pass


def command_text(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"+ {command_text(argv)}", flush=True)
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=capture,
        check=True,
    )


def output(argv: list[str], *, cwd: Path | None = None) -> str:
    return run(argv, cwd=cwd, capture=True).stdout.strip()


def load_manifest() -> dict:
    with MANIFEST_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    if data.get("schema") != 3:
        raise CompatError(f"{MANIFEST_PATH}: unsupported schema {data.get('schema')!r}")
    return data


def load_inventory() -> dict[str, tuple[str, str | None]]:
    inventory: dict[str, tuple[str, str | None]] = {}
    previous = ""
    for lineno, raw in enumerate(INVENTORY_PATH.read_text().splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 3:
            raise CompatError(f"{INVENTORY_PATH}:{lineno}: expected 3 tab-separated fields")
        name, classification, reason = fields
        if name <= previous:
            raise CompatError(f"{INVENTORY_PATH}:{lineno}: inventory must be sorted and unique")
        if classification not in VALID_CLASSES:
            raise CompatError(
                f"{INVENTORY_PATH}:{lineno}: unknown classification {classification!r}"
            )
        inventory[name] = (classification, None if reason == "-" else reason)
        previous = name
    return inventory


def load_regressions() -> dict:
    with REGRESSIONS_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    if data.get("schema") != 1:
        raise CompatError(
            f"{REGRESSIONS_PATH}: unsupported schema {data.get('schema')!r}"
        )
    return data


def upstream_test_names(source: Path) -> set[str]:
    tree = output(
        ["git", "ls-tree", "-r", "--name-only", "HEAD", "testsuite"], cwd=source
    )
    suffix = "_test.py"
    return {
        Path(path).name[: -len(suffix)]
        for path in tree.splitlines()
        if path.endswith(suffix)
    }


def upstream_test_name(test: dict) -> str:
    return test.get("upstream_test", test["name"])


def validate_ledger(manifest: dict, inventory: dict[str, tuple[str, str | None]], source: Path) -> None:
    reasons = manifest.get("reasons", {})
    tests = manifest.get("tests", [])
    target = manifest.get("target", {})
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9-]*", target.get("name", ""))
        or not isinstance(target.get("args"), list)
        or not all(isinstance(arg, str) for arg in target.get("args", []))
    ):
        raise CompatError(f"{MANIFEST_PATH}: target requires a name and string args")
    configured: dict[str, dict] = {}
    configured_sources: set[str] = set()
    for test in tests:
        name = test.get("name")
        if not name or name in configured:
            raise CompatError(f"{MANIFEST_PATH}: missing or duplicate test name {name!r}")
        configured[name] = test
        source_name = upstream_test_name(test)
        configured_sources.add(source_name)
        classification = test.get("classification")
        if classification not in {"conformance", "adapted"}:
            raise CompatError(f"{MANIFEST_PATH}: {name}: runnable test has bad classification")
        if source_name not in inventory or inventory[source_name][0] != classification:
            raise CompatError(f"{MANIFEST_PATH}: {name}: manifest and inventory disagree")
        if source_name != name and classification != "adapted":
            raise CompatError(
                f"{MANIFEST_PATH}: {name}: only adapted scenarios may name an upstream_test"
            )
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", test.get("area", "")):
            raise CompatError(f"{MANIFEST_PATH}: {name}: missing or invalid area")
        if test.get("position") not in VALID_POSITIONS:
            raise CompatError(f"{MANIFEST_PATH}: {name}: invalid product position")
        if test.get("baseline") not in VALID_OUTCOMES:
            raise CompatError(f"{MANIFEST_PATH}: {name}: invalid observation baseline")
        if classification == "adapted":
            if not test.get("adaptation"):
                raise CompatError(f"{MANIFEST_PATH}: {name}: adapted test has no adaptation id")
            if test.get("adaptation_kind") not in VALID_ADAPTATION_KINDS:
                raise CompatError(f"{MANIFEST_PATH}: {name}: invalid adaptation kind")
        elif test.get("adaptation") or test.get("adaptation_kind"):
            raise CompatError(f"{MANIFEST_PATH}: {name}: unmodified test names an adaptation")

    for name, (classification, reason) in inventory.items():
        if classification in {"conformance", "adapted"} and name not in configured_sources:
            raise CompatError(f"{INVENTORY_PATH}: {name}: runnable test has no manifest entry")
        if classification in {"unsupported", "out-of-scope"}:
            if reason not in reasons:
                raise CompatError(f"{INVENTORY_PATH}: {name}: unknown reason {reason!r}")
        elif reason is not None:
            raise CompatError(f"{INVENTORY_PATH}: {name}: classification must use '-' reason")

    actual = upstream_test_names(source)
    recorded = set(inventory)
    if actual != recorded:
        added = sorted(actual - recorded)
        removed = sorted(recorded - actual)
        detail = []
        if added:
            detail.append("unclassified upstream tests: " + ", ".join(added))
        if removed:
            detail.append("tests no longer upstream: " + ", ".join(removed))
        raise CompatError("pinned rsync inventory drifted; " + "; ".join(detail))


def validate_regressions(regressions: dict, manifest: dict) -> None:
    compat_tests = {test["name"] for test in manifest.get("tests", [])}
    local_source = (ROOT / "tests" / "local.rs").read_text()
    local_tests = set(re.findall(r"(?m)^fn ([a-z0-9_]+)\(\)", local_source))
    seen: set[str] = set()
    for item in regressions.get("regressions", []):
        regression_id = item.get("id", "")
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9-]*", regression_id)
            or regression_id in seen
        ):
            raise CompatError(
                f"{REGRESSIONS_PATH}: missing, invalid, or duplicate id {regression_id!r}"
            )
        seen.add(regression_id)
        if not item.get("title") or not item.get("claim") or not item.get("note"):
            raise CompatError(f"{REGRESSIONS_PATH}: {regression_id}: missing description")
        source_url = item.get("source", "")
        if not source_url.startswith("https://github.com/RsyncProject/rsync/"):
            raise CompatError(
                f"{REGRESSIONS_PATH}: {regression_id}: source must be an official rsync URL"
            )
        if item.get("priority") not in VALID_REGRESSION_PRIORITIES:
            raise CompatError(f"{REGRESSIONS_PATH}: {regression_id}: invalid priority")
        if item.get("impact") not in VALID_REGRESSION_IMPACTS:
            raise CompatError(f"{REGRESSIONS_PATH}: {regression_id}: invalid impact")
        status = item.get("status")
        if status not in VALID_REGRESSION_STATUSES:
            raise CompatError(f"{REGRESSIONS_PATH}: {regression_id}: invalid status")
        compat_refs = item.get("compat_tests", [])
        local_refs = item.get("local_tests", [])
        if not all(isinstance(name, str) for name in [*compat_refs, *local_refs]):
            raise CompatError(f"{REGRESSIONS_PATH}: {regression_id}: test refs must be strings")
        unknown_compat = sorted(set(compat_refs) - compat_tests)
        unknown_local = sorted(set(local_refs) - local_tests)
        if unknown_compat or unknown_local:
            raise CompatError(
                f"{REGRESSIONS_PATH}: {regression_id}: unknown test refs "
                + ", ".join(unknown_compat + unknown_local)
            )
        if status in {"covered", "partial"} and not compat_refs and not local_refs:
            raise CompatError(
                f"{REGRESSIONS_PATH}: {regression_id}: {status} entry has no executable test"
            )


def verify_source(source: Path, commit: str) -> None:
    if not (source / ".git").exists():
        raise CompatError(f"{source} is not a git checkout")
    got = output(["git", "rev-parse", "HEAD"], cwd=source)
    if got != commit:
        raise CompatError(f"{source} is at {got}, expected pinned rsync commit {commit}")


def fetch_source(cache: Path, repository: str, commit: str) -> Path:
    sources = cache / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    destination = sources / commit
    if destination.exists():
        verify_source(destination, commit)
        return destination

    temporary = Path(tempfile.mkdtemp(prefix=f".{commit[:12]}-", dir=sources))
    try:
        run(["git", "init", "--quiet"], cwd=temporary)
        run(["git", "remote", "add", "origin", repository], cwd=temporary)
        run(["git", "fetch", "--depth=1", "origin", commit], cwd=temporary)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=temporary)
        verify_source(temporary, commit)
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def helpers_ready(source: Path, helpers: list[str]) -> bool:
    return all((source / helper).is_file() for helper in helpers) and all(
        (source / name).is_file() for name in ("config.h", "shconfig", "Makefile")
    )


def git_patch_paths(adaptation: str, patch: bytes, *, reverse: bool) -> set[bytes]:
    argv = ["git", "apply"]
    if reverse:
        argv.append("-R")
    argv.extend(["--numstat", "-z", "-"])
    result = subprocess.run(
        argv,
        cwd=ROOT,
        input=patch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CompatError(f"adaptation {adaptation!r} is not a valid patch: {detail}")
    paths: set[bytes] = set()
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        fields = record.split(b"\t", 2)
        if len(fields) != 3 or not fields[2]:
            raise CompatError(f"adaptation {adaptation!r} has malformed git numstat output")
        paths.add(fields[2])
    return paths


def validate_adaptation_patch(adaptation: str, patch: bytes) -> None:
    # Forward numstat exposes destinations; reverse numstat exposes rename and
    # copy sources. Git is also the parser that will apply these exact bytes.
    paths = git_patch_paths(adaptation, patch, reverse=False)
    paths.update(git_patch_paths(adaptation, patch, reverse=True))
    if not paths or any(
        not path.startswith(b"testsuite/") or b".." in path.split(b"/")
        for path in paths
    ):
        raise CompatError(
            f"adaptation {adaptation!r} must change only upstream testsuite files"
        )


def load_adaptations(adaptations: list[str]) -> dict[str, bytes]:
    loaded: dict[str, bytes] = {}
    for adaptation in adaptations:
        path = COMPAT_DIR / "adaptations" / f"{adaptation}.patch"
        if not path.is_file():
            raise CompatError(f"adaptation {adaptation!r} has no patch at {path}")
        patch = path.read_bytes()
        validate_adaptation_patch(adaptation, patch)
        loaded[adaptation] = patch
    return loaded


def suite_key(manifest: dict, commit: str, adaptations: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(commit.encode())
    digest.update(json.dumps(manifest["upstream"]["configure_args"]).encode())
    digest.update(json.dumps(manifest["upstream"]["helpers"]).encode())
    for adaptation, patch in adaptations.items():
        digest.update(adaptation.encode())
        digest.update(patch)
    return digest.hexdigest()[:20]


def prepare_base_suite(
    source: Path,
    cache: Path,
    manifest: dict,
    jobs: int,
    source_was_explicit: bool,
) -> Path:
    helpers = list(manifest["upstream"]["helpers"])
    if source_was_explicit and helpers_ready(source, helpers):
        return source

    key = suite_key(manifest, manifest["upstream"]["commit"], {})
    suites = cache / "suites"
    suites.mkdir(parents=True, exist_ok=True)
    destination = suites / key
    marker = destination / ".syq-rsync-suite.json"
    if marker.is_file() and helpers_ready(destination, helpers):
        return destination
    if destination.exists():
        raise CompatError(f"incomplete generated suite at {destination}; remove it and retry")

    temporary = Path(tempfile.mkdtemp(prefix=f".{key}-", dir=suites))
    try:
        shutil.rmtree(temporary)
        run(["git", "clone", "--quiet", "--no-local", str(source), str(temporary)])
        run(
            ["git", "checkout", "--detach", manifest["upstream"]["commit"]],
            cwd=temporary,
        )
        for tool in ("make", "autoconf", "autoheader", "aclocal"):
            if shutil.which(tool) is None:
                raise CompatError(f"preparing rsync tests requires {tool} on PATH")
        run(["./prepare-source", "build"], cwd=temporary)
        run(["./configure", *manifest["upstream"]["configure_args"]], cwd=temporary)
        run(["make", f"-j{jobs}", *helpers], cwd=temporary)
        (temporary / marker.name).write_text(
            json.dumps(
                {
                    "commit": manifest["upstream"]["commit"],
                    "adaptations": [],
                },
                sort_keys=True,
            )
            + "\n"
        )
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def prepare_suite(
    source: Path,
    cache: Path,
    manifest: dict,
    adaptations: dict[str, bytes],
    jobs: int,
    source_was_explicit: bool,
) -> Path:
    base = prepare_base_suite(source, cache, manifest, jobs, source_was_explicit)
    if not adaptations:
        return base

    helpers = list(manifest["upstream"]["helpers"])
    key = suite_key(manifest, manifest["upstream"]["commit"], adaptations)
    suites = cache / "suites"
    suites.mkdir(parents=True, exist_ok=True)
    destination = suites / key
    marker = destination / ".syq-rsync-suite.json"
    if marker.is_file() and helpers_ready(destination, helpers):
        return destination
    if destination.exists():
        raise CompatError(f"incomplete generated suite at {destination}; remove it and retry")

    temporary = Path(tempfile.mkdtemp(prefix=f".{key}-", dir=suites))
    try:
        shutil.rmtree(temporary)
        print(f"+ copy configured suite {base} -> {temporary}", flush=True)
        shutil.copytree(
            base,
            temporary,
            symlinks=True,
            ignore=shutil.ignore_patterns("testtmp", "__pycache__"),
        )
        for adaptation, patch in adaptations.items():
            print(f"+ git apply --whitespace=nowarn {adaptation}.patch", flush=True)
            subprocess.run(
                ["git", "apply", "--whitespace=nowarn", "-"],
                cwd=temporary,
                input=patch,
                check=True,
            )
        (temporary / marker.name).write_text(
            json.dumps(
                {
                    "commit": manifest["upstream"]["commit"],
                    "adaptations": list(adaptations),
                },
                sort_keys=True,
            )
            + "\n"
        )
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def platform_name() -> str:
    system = platform.system().lower()
    return {"darwin": "macos"}.get(system, system)


def running_as() -> str:
    return "root" if hasattr(os, "geteuid") and os.geteuid() == 0 else "non-root"


def select_tests(
    manifest: dict, selected_areas: set[str] | None = None
) -> tuple[list[dict], list[dict], list[dict]]:
    selected: list[dict] = []
    environment_excluded: list[dict] = []
    selection_excluded: list[dict] = []
    current_platform = platform_name()
    for test in manifest.get("tests", []):
        if selected_areas and test["area"] not in selected_areas:
            selection_excluded.append(test)
            continue
        platforms = test.get("platforms", [])
        if platforms and current_platform not in platforms:
            environment_excluded.append(test)
            continue
        required_user = test.get("run_as")
        if required_user and required_user != running_as():
            environment_excluded.append(test)
            continue
        selected.append(test)
    return selected, environment_excluded, selection_excluded


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def provenance(test: dict) -> str:
    if test["classification"] == "conformance":
        return "unmodified upstream"
    result = f"{test['adaptation_kind']} adaptation ({test['adaptation']})"
    source_name = upstream_test_name(test)
    if source_name != test["name"]:
        result += f" of upstream {source_name}"
    return result


def render_ledger(manifest: dict, inventory: dict[str, tuple[str, str | None]]) -> str:
    counts = collections.Counter(value[0] for value in inventory.values())
    runnable = {test["name"]: test for test in manifest.get("tests", [])}
    lines = [
        "# Upstream rsync test ledger",
        "",
        "This file is generated from `manifest.toml` and `inventory.tsv`. Update it with:",
        "",
        "```sh",
        "python3 scripts/rsync-compat.py --ledger-only --update-ledger",
        "```",
        "",
        f"Pinned rsync commit: `{manifest['upstream']['commit']}`.",
        "Configured command prefix: `syq"
        + "".join(f" {shlex.quote(arg)}" for arg in manifest["target"]["args"])
        + "`.",
        "",
        "| Classification | Tests |",
        "|---|---:|",
    ]
    for classification in ("conformance", "adapted", "unsupported", "out-of-scope", "unassessed"):
        lines.append(f"| {classification} | {counts[classification]} |")

    lines.extend(
        [
            "",
            "## Runnable behavioral tests",
            "",
            "The baseline is the last reviewed observation, not a claim that rsync's "
            "behavior is always the desired product policy.",
            "",
            "| Area | Test | Baseline | Product position | Provenance | Circumstances | Note |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for test in sorted(runnable.values(), key=lambda item: (item["area"], item["name"])):
        name = test["name"]
        circumstances = []
        if test.get("platforms"):
            circumstances.append("platform=" + ",".join(test["platforms"]))
        if test.get("run_as"):
            circumstances.append("run-as=" + test["run_as"])
        circumstances.extend(test.get("requirements", []))
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in (
                    test["area"],
                    f"`{name}`",
                    test["baseline"],
                    POSITION_LABELS[test["position"]],
                    provenance(test),
                    "; ".join(circumstances) or "portable",
                    test.get("note", ""),
                )
            )
            + " |"
        )

    reasons = manifest.get("reasons", {})
    lines.extend(["", "## Exclusion reasons", "", "| Reason | Meaning |", "|---|---|"])
    for reason, meaning in sorted(reasons.items()):
        lines.append(f"| `{reason}` | {markdown_cell(meaning)} |")

    for classification, title in (
        ("unsupported", "Unsupported user-facing features"),
        ("out-of-scope", "Rsync-specific internals, protocol, and services"),
        ("unassessed", "Not yet assessed"),
    ):
        names = [
            (name, reason)
            for name, (recorded_class, reason) in inventory.items()
            if recorded_class == classification
        ]
        if not names:
            continue
        lines.extend(["", f"## {title}", "", "| Test | Reason |", "|---|---|"])
        for name, reason in names:
            lines.append(f"| `{name}` | {f'`{reason}`' if reason else '-'} |")
    lines.append("")
    return "\n".join(lines)


def render_regressions(regressions: dict) -> str:
    counts = collections.Counter(
        item["status"] for item in regressions.get("regressions", [])
    )
    lines = [
        "# Historical rsync regression corpus",
        "",
        "This generated ledger turns selected upstream bug reports, security policy,",
        "advisories, and regression tests into reviewable behavioral claims for SYQ.",
        "It prioritizes security, data loss, and data integrity; it is deliberately",
        "curated rather than a claim that every rsync issue applies to SYQ.",
        "",
        "Update it with:",
        "",
        "```sh",
        "python3 scripts/rsync-compat.py --ledger-only --update-ledger",
        "```",
        "",
        "| Status | Cases |",
        "|---|---:|",
    ]
    for status in ("covered", "partial", "candidate", "not-applicable"):
        lines.append(f"| {status} | {counts[status]} |")
    lines.extend(
        [
            "",
            "`covered` means the recorded behavioral claim has executable coverage,",
            "not that SYQ implements every option or internal mechanism in the report.",
            "`partial` identifies the untested remainder explicitly; `candidate` is",
            "triaged future work; `not-applicable` records a deliberate exclusion.",
            "",
            "| Priority | Impact | Case | Status | Behavioral claim | Executable coverage | Note |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for item in sorted(
        regressions.get("regressions", []),
        key=lambda row: (priority_order[row["priority"]], row["id"]),
    ):
        refs = [f"compat:`{name}`" for name in item.get("compat_tests", [])]
        refs.extend(f"local:`{name}`" for name in item.get("local_tests", []))
        source = f"[{item['id']}]({item['source']}) — {item['title']}"
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in (
                    item["priority"],
                    item["impact"],
                    source,
                    item["status"],
                    item["claim"],
                    "; ".join(refs) or "none",
                    item["note"],
                )
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def check_ledger(
    manifest: dict,
    inventory: dict[str, tuple[str, str | None]],
    regressions: dict,
    *,
    update: bool,
) -> None:
    rendered = render_ledger(manifest, inventory)
    rendered_regressions = render_regressions(regressions)
    if update:
        LEDGER_PATH.write_text(rendered)
        REGRESSIONS_LEDGER_PATH.write_text(rendered_regressions)
    if not LEDGER_PATH.is_file() or LEDGER_PATH.read_text() != rendered:
        raise CompatError(
            f"{LEDGER_PATH} is stale; run with --ledger-only --update-ledger"
        )
    if (
        not REGRESSIONS_LEDGER_PATH.is_file()
        or REGRESSIONS_LEDGER_PATH.read_text() != rendered_regressions
    ):
        raise CompatError(
            f"{REGRESSIONS_LEDGER_PATH} is stale; run with --ledger-only --update-ledger"
        )


def make_wrapper(path: Path, syq: Path, extra_args: list[str]) -> None:
    body = (
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        f"binary = {str(syq)!r}\n"
        f"extra = {extra_args!r}\n"
        "os.execv(binary, [binary, *extra, *sys.argv[1:]])\n"
    )
    path.write_text(body)
    path.chmod(0o755)


def stream_command(argv: list[str], *, cwd: Path, env: dict[str, str]) -> tuple[int, str]:
    print(f"+ {command_text(argv)}", flush=True)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    lines: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        lines.append(line)
    process.stdout.close()
    return process.wait(), "".join(lines)


def parse_results(
    log: str, expected_names: set[str]
) -> tuple[dict[str, str], list[str]]:
    outcomes: dict[str, str] = {}
    errors: list[str] = []
    inside_test_log = False
    for line in log.splitlines():
        if line.startswith("----- ") and line.endswith(" log follows"):
            inside_test_log = True
            continue
        if inside_test_log and line.startswith("----- ") and line.endswith(" log ends"):
            inside_test_log = False
            continue
        if inside_test_log:
            continue
        match = RESULT_RE.match(line)
        if not match:
            continue
        name = match.group(2)
        outcome = match.group(1).lower()
        if name not in expected_names:
            errors.append(f"unexpected result for {name}: {outcome}")
        elif name in outcomes:
            errors.append(
                f"duplicate result for {name}: kept {outcomes[name]}, ignored {outcome}"
            )
        else:
            outcomes[name] = outcome
    if inside_test_log:
        errors.append("runner output ended inside a framed test log")
    for name in sorted(expected_names - outcomes.keys()):
        errors.append(f"missing result for {name}")
    return outcomes, errors


def assess_harness(
    runner_exit_code: int,
    outcomes: dict[str, str],
    parser_errors: list[str],
    *,
    require_tests: bool,
    applicable: int,
) -> tuple[int, list[str]]:
    expected_exit_code = sum(outcome == "fail" for outcome in outcomes.values())
    errors = list(parser_errors)
    if runner_exit_code != expected_exit_code:
        errors.append(
            f"runner exit code {runner_exit_code} disagrees with "
            f"{expected_exit_code} observed test failure(s)"
        )
    if require_tests and applicable == 0:
        errors.append("no tests apply under these circumstances")
    return expected_exit_code, errors


def markdown_report(report: dict) -> str:
    command = command_text(["syq", *report["target_args"]])
    area_selection = ""
    if report.get("selected_areas"):
        area_selection = " · areas: `" + ", ".join(report["selected_areas"]) + "`"
    if report["harness_ok"]:
        harness_status = (
            "Harness execution: **complete** — runner exit code "
            f"`{report['runner_exit_code']}` agrees with "
            f"{report['expected_runner_exit_code']} observed test failure(s)."
        )
    else:
        harness_status = "Harness execution: **FAILED**."
    lines = [
        "## rsync behavioral compatibility matrix",
        "",
        f"Pinned upstream: `{report['upstream_commit']}` · target: `{report['target_name']}` "
        f"via `{command}` "
        f"· platform: `{report['platform']}` · run as: `{report['run_as']}`"
        f"{area_selection}",
        "",
        harness_status,
        "",
        "### Product positions",
        "",
        "| Position | Applicable tests |",
        "|---|---:|",
    ]
    for position, label in POSITION_LABELS.items():
        lines.append(f"| {label} | {report['position_counts'].get(position, 0)} |")
    lines.extend(
        [
            f"| **Total applicable** | **{report['applicable']}** |",
            "",
            "Inventory outside this matrix: "
            f"{report['ledger']['unsupported']} unsupported user-facing tests, "
            f"{report['ledger']['out-of-scope']} rsync-internal/out-of-scope tests, "
            f"and {report['ledger']['unassessed']} unassessed tests.",
            "",
            "### Observations",
            "",
        ]
    )
    if report.get("selection_excluded"):
        lines.extend(
            [
                f"Area selection omitted {len(report['selection_excluded'])} other "
                "runnable scenario(s).",
                "",
            ]
        )
    if report.get("environment_excluded"):
        lines.extend(
            [
                f"Platform or user circumstances excluded "
                f"{len(report['environment_excluded'])} selected scenario(s).",
                "",
            ]
        )
    if report["tests"]:
        lines.extend(
            [
                "| Area | Test | Observed | Product position | Provenance | Circumstances | Note |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for test in sorted(report["tests"], key=lambda item: (item["area"], item["name"])):
            observed = test["actual"].upper()
            if not test["baseline_matches"] and test["actual"] != "notrun":
                observed += f" (baseline {test['baseline'].upper()})"
            lines.append(
                "| "
                + " | ".join(
                    markdown_cell(value)
                    for value in (
                        test["area"],
                        f"`{test['name']}`",
                        observed,
                        POSITION_LABELS[test["position"]],
                        provenance(test),
                        "; ".join(test["circumstances"]) or "portable",
                        test["note"],
                    )
                )
                + " |"
            )
    else:
        lines.append("No tests apply under these platform and user circumstances.")
    lines.extend(
        [
            "",
            "### Unsupported feature areas",
            "",
            "These user-facing areas are tracked but not yet useful to run through "
            "their upstream tests.",
            "",
            "| Feature area | Upstream tests | Current limitation |",
            "|---|---:|---|",
        ]
    )
    for feature in report["unsupported_features"]:
        lines.append(
            f"| `{feature['area']}` | {feature['tests']} | "
            f"{markdown_cell(feature['description'])} |"
        )
    changes = [test for test in report["tests"] if not test["baseline_matches"]]
    if changes:
        lines.extend(["", "### Observation changes requiring review", ""])
        lines.extend(
            f"- `{test['name']}`: baseline {test['baseline']}, observed {test['actual']}"
            for test in changes
        )
    if report["harness_errors"]:
        lines.extend(["", "### Harness errors", ""])
        lines.extend(f"- {error}" for error in report["harness_errors"])
    lines.append("")
    return "\n".join(lines)


def html_report(report: dict) -> str:
    command = command_text(["syq", *report["target_args"]])
    area_selection = ""
    if report.get("selected_areas"):
        area_selection = " · areas: " + escape(", ".join(report["selected_areas"]))
    cards = "".join(
        '<div class="card"><strong>'
        + str(report["position_counts"].get(position, 0))
        + "</strong><span>"
        + escape(label)
        + "</span></div>"
        for position, label in POSITION_LABELS.items()
    )
    rows = []
    for test in sorted(report["tests"], key=lambda item: (item["area"], item["name"])):
        observed = test["actual"].upper()
        if not test["baseline_matches"] and test["actual"] != "notrun":
            observed += f" (baseline {test['baseline'].upper()})"
        rows.append(
            '<tr class="' + ("changed" if not test["baseline_matches"] else "") + '">'
            f"<td>{escape(test['area'])}</td>"
            f"<td><code>{escape(test['name'])}</code></td>"
            f'<td><span class="badge result-{escape(test["actual"])}">{escape(observed)}</span></td>'
            f'<td><span class="badge position-{escape(test["position"])}">'
            f"{escape(POSITION_LABELS[test['position']])}</span></td>"
            f"<td>{escape(provenance(test))}</td>"
            f"<td>{escape('; '.join(test['circumstances']) or 'portable')}</td>"
            f"<td>{escape(test['note'])}</td></tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="7">No tests apply under these circumstances.</td></tr>')
    harness_errors = ""
    if report["harness_errors"]:
        harness_errors = '<section class="alert"><h2>Harness errors</h2><ul>' + "".join(
            f"<li>{escape(error)}</li>" for error in report["harness_errors"]
        ) + "</ul></section>"
    changes = [test for test in report["tests"] if not test["baseline_matches"]]
    change_notice = ""
    if changes:
        change_notice = (
            '<section class="alert"><h2>Observation changes requiring review</h2><ul>'
            + "".join(
                f"<li><code>{escape(test['name'])}</code>: baseline "
                f"{escape(test['baseline'])}, observed {escape(test['actual'])}</li>"
                for test in changes
            )
            + "</ul></section>"
        )
    legend = "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(POSITION_DESCRIPTIONS[position])}</dd>"
        for position, label in POSITION_LABELS.items()
    )
    unsupported_rows = "".join(
        f"<tr><td><code>{escape(feature['area'])}</code></td>"
        f"<td>{feature['tests']}</td><td>{escape(feature['description'])}</td></tr>"
        for feature in report["unsupported_features"]
    )
    harness_class = "ok" if report["harness_ok"] else "bad"
    harness_text = (
        "Execution complete; runner status agrees with observed outcomes."
        if report["harness_ok"]
        else "Harness execution failed; results may be incomplete."
    )
    selection_notes = ""
    if report.get("selection_excluded"):
        selection_notes += (
            f"<p>Area selection omitted {len(report['selection_excluded'])} other "
            "runnable scenario(s).</p>"
        )
    if report.get("environment_excluded"):
        selection_notes += (
            f"<p>Platform or user circumstances excluded "
            f"{len(report['environment_excluded'])} selected scenario(s).</p>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SYQ rsync behavioral matrix</title><style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 1500px; margin: 2rem auto; padding: 0 1rem; line-height: 1.45; }}
code {{ font-family: ui-monospace, monospace; }}
.meta {{ color: #68707a; }} .status {{ padding: .75rem 1rem; border-radius: .5rem; }}
.status.ok {{ background: #d8f3dc; color: #16351d; }} .status.bad, .alert {{ background: #ffe3e3; color: #4b1111; }}
.cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin: 1.25rem 0; }}
.card {{ border: 1px solid #9aa0a6; border-radius: .5rem; padding: .7rem 1rem; min-width: 9rem; }}
.card strong {{ display: block; font-size: 1.5rem; }} .card span {{ font-size: .9rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: .92rem; }}
th, td {{ border: 1px solid #9aa0a6; padding: .55rem; text-align: left; vertical-align: top; }}
th {{ position: sticky; top: 0; background: Canvas; }} tr.changed {{ outline: 2px solid #d97706; }}
.badge {{ display: inline-block; border-radius: 999px; padding: .12rem .5rem; white-space: nowrap; background: #e5e7eb; color: #111827; }}
.result-pass, .position-compatible {{ background: #d8f3dc; color: #16351d; }}
.result-fail, .position-unimplemented {{ background: #ffe3e3; color: #4b1111; }}
.position-intentional-divergence {{ background: #dbeafe; color: #172554; }}
.position-policy-open, .position-test-unresolved {{ background: #fef3c7; color: #451a03; }}
.alert {{ padding: .75rem 1rem; border-radius: .5rem; margin: 1rem 0; }}
dt {{ font-weight: 700; margin-top: .5rem; }} dd {{ margin-left: 1.25rem; }}
@media (prefers-color-scheme: dark) {{ .meta {{ color: #b0b8c1; }} }}
</style></head><body>
<h1>SYQ rsync behavioral compatibility matrix</h1>
<p class="meta">Pinned rsync <code>{escape(report['upstream_commit'])}</code> · target
<code>{escape(report['target_name'])}</code> via <code>{escape(command)}</code> ·
{escape(report['platform'])} · {escape(report['run_as'])}{area_selection}</p>
<p class="status {harness_class}">{escape(harness_text)}</p>{selection_notes}
<div class="cards">{cards}</div>{harness_errors}{change_notice}
<h2>Observed tests</h2><table><thead><tr><th>Area</th><th>Test</th><th>Observed</th>
<th>Product position</th><th>Provenance</th><th>Circumstances</th><th>Note</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Position legend</h2><dl>{legend}</dl>
<h2>Unsupported feature areas</h2><p>Tracked user-facing areas whose upstream tests are
not yet useful to run against the target.</p><table><thead><tr><th>Feature area</th>
<th>Upstream tests</th><th>Current limitation</th></tr></thead><tbody>{unsupported_rows}</tbody></table>
<h2>Excluded inventory</h2><p>{report['ledger']['out-of-scope']} rsync-internal or
out-of-scope tests are omitted; {report['ledger']['unassessed']} tests remain unassessed.</p>
</body></html>"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SYQ's classified compatibility subset of a pinned rsync test suite"
    )
    parser.add_argument(
        "--syq-bin",
        type=Path,
        help="SYQ binary (defaults to the Cargo target directory's debug/syq)",
    )
    parser.add_argument("--no-build-syq", action="store_true")
    parser.add_argument("--rsync-src", type=Path, help="reuse an existing checkout at the pin")
    parser.add_argument(
        "--cache-dir", type=Path, default=ROOT / "target" / "rsync-compat"
    )
    parser.add_argument("-j", "--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=300,
        metavar="SECONDS",
        help="per-test timeout passed to the upstream runner (default: 300)",
    )
    parser.add_argument("--preserve-scratch", action="store_true")
    parser.add_argument("--ledger-only", action="store_true")
    parser.add_argument("--update-ledger", action="store_true")
    parser.add_argument(
        "--area",
        action="append",
        default=[],
        metavar="NAME",
        help="run only manifest tests in this behavioral area (repeatable)",
    )
    parser.add_argument(
        "--require-tests",
        action="store_true",
        help="fail after writing reports if no tests apply (used by CI)",
    )
    parser.add_argument(
        "--report-label",
        help="append a safe label to report filenames (for example, root)",
    )
    return parser.parse_args()


def default_syq_binary() -> Path:
    target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    if not target.is_absolute():
        target = ROOT / target
    return target / "debug" / "syq"


def main() -> int:
    args = parse_args()
    if args.jobs < 1:
        raise CompatError("--jobs must be positive")
    if args.test_timeout < 1:
        raise CompatError("--test-timeout must be positive")
    if args.report_label and not re.fullmatch(r"[A-Za-z0-9_-]+", args.report_label):
        raise CompatError("--report-label may contain only letters, digits, _ and -")
    manifest = load_manifest()
    inventory = load_inventory()
    regressions = load_regressions()
    target = manifest["target"]
    selected_areas = set(args.area)
    available_areas = {test["area"] for test in manifest.get("tests", [])}
    unknown_areas = sorted(selected_areas - available_areas)
    if unknown_areas:
        raise CompatError(
            "unknown --area value(s): "
            + ", ".join(unknown_areas)
            + "; available areas: "
            + ", ".join(sorted(available_areas))
        )

    cache = args.cache_dir.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    upstream = manifest["upstream"]
    source_was_explicit = args.rsync_src is not None
    if source_was_explicit:
        source = args.rsync_src.resolve()
        verify_source(source, upstream["commit"])
    else:
        source = fetch_source(cache, upstream["repository"], upstream["commit"])
    validate_ledger(manifest, inventory, source)
    validate_regressions(regressions, manifest)
    check_ledger(manifest, inventory, regressions, update=args.update_ledger)
    if args.ledger_only:
        return 0

    selected, environment_excluded, selection_excluded = select_tests(
        manifest, selected_areas
    )
    adaptation_ids = sorted(
        {test["adaptation"] for test in selected if test.get("adaptation")}
    )
    run_dir: Path | None = None
    runner_exit_code = 0
    log = ""
    actual: dict[str, str] = {}
    parser_errors: list[str] = []
    if selected:
        adaptations = load_adaptations(adaptation_ids)
        suite = prepare_suite(
            source, cache, manifest, adaptations, args.jobs, source_was_explicit
        )

        syq = (args.syq_bin or default_syq_binary()).resolve()
        if not args.no_build_syq:
            run(["cargo", "build", "--locked", "--bin", "syq"], cwd=ROOT)
        if not syq.is_file():
            raise CompatError(f"SYQ binary not found at {syq}")

        # Root-only upstream tests may execute the wrapper after dropping to a
        # second uid. CI workspace ancestors are not guaranteed to be traversable
        # by that uid, so keep root-run scratch space under the shared system tmp.
        run_parent = Path("/tmp") if running_as() == "root" else cache
        run_dir = Path(
            tempfile.mkdtemp(prefix=f"syq-rsync-{target['name']}-", dir=run_parent)
        )
        # Some upstream security tests deliberately drop privileges. They still
        # need to traverse this directory to execute the generated SYQ wrapper.
        run_dir.chmod(0o755)
        run_binary = syq
        if running_as() == "root":
            run_binary = run_dir / "syq"
            shutil.copy2(syq, run_binary)
            run_binary.chmod(0o755)
        wrapper = run_dir / "syq-rsync"
        make_wrapper(wrapper, run_binary, list(target.get("args", [])))
        scratch = run_dir / "scratch"
        scratch.mkdir()
        runner_args = [
            sys.executable,
            str(suite / "runtests.py"),
            "--rsync-bin",
            str(wrapper),
            "--tooldir",
            str(suite),
            "--srcdir",
            str(suite),
            "--timeout",
            str(args.test_timeout),
            "--timing",
            "-j",
            str(args.jobs),
        ]
        if args.preserve_scratch:
            runner_args.append("--preserve-scratch")
        runner_args.extend(test["name"] for test in selected)
        env = os.environ.copy()
        env["scratchbase"] = str(scratch)
        runner_exit_code, log = stream_command(runner_args, cwd=suite, env=env)
        actual, parser_errors = parse_results(
            log, {test["name"] for test in selected}
        )
    else:
        log = "No upstream tests apply under these circumstances.\n"

    test_results = []
    for test in selected:
        name = test["name"]
        got = actual.get(name, "notrun")
        circumstances = []
        if test.get("platforms"):
            circumstances.append("platform=" + ",".join(test["platforms"]))
        if test.get("run_as"):
            circumstances.append("run-as=" + test["run_as"])
        circumstances.extend(test.get("requirements", []))
        test_results.append(
            {
                "name": name,
                "upstream_test": upstream_test_name(test),
                "classification": test["classification"],
                "adaptation": test.get("adaptation"),
                "adaptation_kind": test.get("adaptation_kind"),
                "area": test["area"],
                "position": test["position"],
                "baseline": test["baseline"],
                "actual": got,
                "baseline_matches": got == test["baseline"],
                "tags": test.get("tags", []),
                "requirements": test.get("requirements", []),
                "circumstances": circumstances,
                "note": test.get("note", ""),
            }
        )

    ledger_counts = collections.Counter(value[0] for value in inventory.values())
    applicable = len(test_results)
    expected_runner_exit_code, harness_errors = assess_harness(
        runner_exit_code,
        actual,
        parser_errors,
        require_tests=args.require_tests,
        applicable=applicable,
    )
    position_counts = collections.Counter(test["position"] for test in test_results)
    observed_counts = collections.Counter(test["actual"] for test in test_results)
    unsupported_counts = collections.Counter(
        reason
        for classification, reason in inventory.values()
        if classification == "unsupported"
    )
    unsupported_features = [
        {
            "area": reason.removeprefix("unsupported-"),
            "reason": reason,
            "tests": count,
            "description": manifest["reasons"][reason],
        }
        for reason, count in sorted(unsupported_counts.items())
    ]
    report = {
        "schema": 2,
        "upstream_repository": upstream["repository"],
        "upstream_commit": upstream["commit"],
        "target_name": target["name"],
        "target_args": target.get("args", []),
        "target_description": target.get("description", ""),
        "platform": platform_name(),
        "run_as": running_as(),
        "selected_areas": sorted(selected_areas),
        "applicable": applicable,
        "observed_counts": dict(sorted(observed_counts.items())),
        "position_counts": dict(sorted(position_counts.items())),
        "adapted": sum(test["classification"] == "adapted" for test in test_results),
        "environment_excluded": [test["name"] for test in environment_excluded],
        "selection_excluded": [test["name"] for test in selection_excluded],
        "unsupported_features": unsupported_features,
        "ledger": {key: ledger_counts[key] for key in sorted(VALID_CLASSES)},
        "tests": test_results,
        "runner_exit_code": runner_exit_code,
        "expected_runner_exit_code": expected_runner_exit_code,
        "parser_errors": parser_errors,
        "harness_errors": harness_errors,
        "harness_ok": not harness_errors,
    }
    reports = cache / "reports"
    reports.mkdir(exist_ok=True)
    report_stem = target["name"] + (f"-{args.report_label}" if args.report_label else "")
    report_json = reports / f"{report_stem}.json"
    report_md = reports / f"{report_stem}.md"
    report_html = reports / f"{report_stem}.html"
    report_log = reports / f"{report_stem}.log"
    report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = markdown_report(report)
    report_md.write_text(summary)
    report_html.write_text(html_report(report))
    report_log.write_text(log)
    print("\n" + summary, flush=True)
    if github_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(github_summary).open("a") as handle:
            handle.write(summary)

    if run_dir is not None and not args.preserve_scratch:
        shutil.rmtree(run_dir, ignore_errors=True)
    baseline_changes = [test for test in test_results if not test["baseline_matches"]]
    return 1 if harness_errors or baseline_changes else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CompatError, subprocess.CalledProcessError) as error:
        print(f"rsync-compat: {error}", file=sys.stderr)
        raise SystemExit(2)
