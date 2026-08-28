#!/usr/bin/env python3
"""Run SYQ against a pinned, classified subset of the upstream rsync suite."""

from __future__ import annotations

import argparse
import collections
import hashlib
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
VALID_CLASSES = {"conformance", "adapted", "unsupported", "out-of-scope", "unassessed"}
VALID_OUTCOMES = {"pass", "fail", "skip", "xfail"}
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
    if data.get("schema") != 1:
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


def validate_ledger(manifest: dict, inventory: dict[str, tuple[str, str | None]], source: Path) -> None:
    reasons = manifest.get("reasons", {})
    tests = manifest.get("tests", [])
    configured: dict[str, dict] = {}
    for test in tests:
        name = test.get("name")
        if not name or name in configured:
            raise CompatError(f"{MANIFEST_PATH}: missing or duplicate test name {name!r}")
        configured[name] = test
        classification = test.get("classification")
        if classification not in {"conformance", "adapted"}:
            raise CompatError(f"{MANIFEST_PATH}: {name}: runnable test has bad classification")
        if name not in inventory or inventory[name][0] != classification:
            raise CompatError(f"{MANIFEST_PATH}: {name}: manifest and inventory disagree")
        for profile_name, expected in test.get("expect", {}).items():
            if profile_name not in manifest.get("profiles", {}):
                raise CompatError(f"{MANIFEST_PATH}: {name}: unknown profile {profile_name!r}")
            if expected not in VALID_OUTCOMES:
                raise CompatError(f"{MANIFEST_PATH}: {name}: bad expected outcome {expected!r}")
        if classification == "adapted" and not test.get("adaptation"):
            raise CompatError(f"{MANIFEST_PATH}: {name}: adapted test has no adaptation id")

    for name, (classification, reason) in inventory.items():
        if classification in {"conformance", "adapted"} and name not in configured:
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


def suite_key(manifest: dict, commit: str, adaptations: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(commit.encode())
    digest.update(json.dumps(manifest["upstream"]["configure_args"]).encode())
    digest.update(json.dumps(manifest["upstream"]["helpers"]).encode())
    for adaptation in adaptations:
        patch = COMPAT_DIR / "adaptations" / f"{adaptation}.patch"
        if not patch.is_file():
            raise CompatError(f"adaptation {adaptation!r} has no patch at {patch}")
        changed_paths = [
            line[6:]
            for line in patch.read_text().splitlines()
            if line.startswith("+++ b/")
        ]
        if not changed_paths or any(
            not path.startswith("testsuite/") for path in changed_paths
        ):
            raise CompatError(
                f"adaptation {adaptation!r} must change only upstream testsuite files"
            )
        digest.update(adaptation.encode())
        digest.update(patch.read_bytes())
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

    key = suite_key(manifest, manifest["upstream"]["commit"], [])
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
    adaptations: list[str],
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
        for adaptation in adaptations:
            patch = COMPAT_DIR / "adaptations" / f"{adaptation}.patch"
            run(["git", "apply", "--whitespace=nowarn", str(patch)], cwd=temporary)
        (temporary / marker.name).write_text(
            json.dumps(
                {
                    "commit": manifest["upstream"]["commit"],
                    "adaptations": adaptations,
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


def select_tests(manifest: dict, profile: str) -> tuple[list[dict], list[dict]]:
    selected: list[dict] = []
    environment_excluded: list[dict] = []
    current_platform = platform_name()
    for test in manifest.get("tests", []):
        platforms = test.get("platforms", [])
        if platforms and current_platform not in platforms:
            environment_excluded.append(test)
            continue
        required_user = test.get("run_as")
        if required_user and required_user != running_as():
            environment_excluded.append(test)
            continue
        if profile not in test.get("expect", {}):
            raise CompatError(f"{MANIFEST_PATH}: {test['name']}: no expectation for {profile}")
        selected.append(test)
    return selected, environment_excluded


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


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
        "",
        "| Classification | Tests |",
        "|---|---:|",
    ]
    for classification in ("conformance", "adapted", "unsupported", "out-of-scope", "unassessed"):
        lines.append(f"| {classification} | {counts[classification]} |")

    lines.extend(["", "## Runnable conformance tests", "", "| Test | Kind | Expected | Circumstances | Note |", "|---|---|---|---|---|"])
    for name, (classification, _) in inventory.items():
        if classification not in {"conformance", "adapted"}:
            continue
        test = runnable[name]
        expected = ", ".join(
            f"{profile}: {outcome}" for profile, outcome in sorted(test.get("expect", {}).items())
        )
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
                    f"`{name}`",
                    classification,
                    expected,
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


def check_ledger(
    manifest: dict,
    inventory: dict[str, tuple[str, str | None]],
    *,
    update: bool,
) -> None:
    rendered = render_ledger(manifest, inventory)
    if update:
        LEDGER_PATH.write_text(rendered)
    if not LEDGER_PATH.is_file() or LEDGER_PATH.read_text() != rendered:
        raise CompatError(
            f"{LEDGER_PATH} is stale; run with --ledger-only --update-ledger"
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
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    lines: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="", flush=True)
        lines.append(line)
    return process.wait(), "".join(lines)


def parse_results(log: str) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for line in log.splitlines():
        match = RESULT_RE.match(line)
        if match:
            outcomes[match.group(2)] = match.group(1).lower()
    return outcomes


def outcome_class(outcome: str) -> str:
    return "fail" if outcome in {"fail", "xfail"} else outcome


def markdown_report(report: dict) -> str:
    lines = [
        "## rsync compatibility",
        "",
        f"Pinned upstream: `{report['upstream_commit']}` · profile: `{report['profile']}` "
        f"· platform: `{report['platform']}` · run as: `{report['run_as']}`",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Applicable tests | {report['applicable']} |",
        f"| Passing | {report['passing']} |",
        f"| Known failures | {report['known_failures']} |",
        f"| Expected skips | {report['skipped']} |",
        f"| Adapted tests | {report['adapted']} |",
        f"| Out of scope (ledger) | {report['ledger']['out-of-scope']} |",
        f"| Unsupported feature (ledger) | {report['ledger']['unsupported']} |",
        f"| Not yet assessed (ledger) | {report['ledger']['unassessed']} |",
        "",
        f"Classified runnable-test pass rate: **{report['passing']}/{report['applicable']} "
        f"({report['score_percent']:.1f}%)**.",
    ]
    gaps = [test for test in report["tests"] if test["actual"] in {"fail", "xfail"}]
    if gaps:
        lines.extend(["", "Known gaps:", ""])
        lines.extend(
            f"- `{test['name']}` ({', '.join(test['tags']) or 'untagged'}): {test['note']}"
            for test in gaps
        )
    mismatches = [test for test in report["tests"] if not test["matches"]]
    if mismatches:
        lines.extend(["", "Expectation mismatches:", ""])
        lines.extend(
            f"- `{test['name']}`: expected {test['expected']}, got {test['actual']}"
            for test in mismatches
        )
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SYQ's classified compatibility subset of a pinned rsync test suite"
    )
    parser.add_argument("--profile", default="default")
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
    parser.add_argument("--preserve-scratch", action="store_true")
    parser.add_argument("--ledger-only", action="store_true")
    parser.add_argument("--update-ledger", action="store_true")
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
    if args.report_label and not re.fullmatch(r"[A-Za-z0-9_-]+", args.report_label):
        raise CompatError("--report-label may contain only letters, digits, _ and -")
    manifest = load_manifest()
    inventory = load_inventory()
    profile = manifest.get("profiles", {}).get(args.profile)
    if profile is None:
        raise CompatError(f"unknown compatibility profile {args.profile!r}")
    if not profile.get("enabled", False):
        raise CompatError(
            f"profile {args.profile!r} is recorded but disabled: {profile['description']}"
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
    check_ledger(manifest, inventory, update=args.update_ledger)
    if args.ledger_only:
        return 0

    selected, environment_excluded = select_tests(manifest, args.profile)
    adaptations = sorted(
        {test["adaptation"] for test in selected if test.get("adaptation")}
    )
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
    run_dir = Path(tempfile.mkdtemp(prefix=f"syq-rsync-{args.profile}-", dir=run_parent))
    # Some upstream security tests deliberately drop privileges. They still
    # need to traverse this directory to execute the generated SYQ wrapper.
    run_dir.chmod(0o755)
    run_binary = syq
    if running_as() == "root":
        run_binary = run_dir / "syq"
        shutil.copy2(syq, run_binary)
        run_binary.chmod(0o755)
    wrapper = run_dir / "syq-rsync"
    make_wrapper(wrapper, run_binary, list(profile.get("args", [])))
    expected = run_dir / "expected.txt"
    expected.write_text(
        "".join(f"{test['name']} {test['expect'][args.profile]}\n" for test in selected)
    )
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
        "--expect-result",
        str(expected),
        "--timing",
        "-j",
        str(args.jobs),
    ]
    if args.preserve_scratch:
        runner_args.append("--preserve-scratch")
    env = os.environ.copy()
    env["scratchbase"] = str(scratch)
    returncode, log = stream_command(runner_args, cwd=suite, env=env)
    actual = parse_results(log)

    test_results = []
    for test in selected:
        name = test["name"]
        got = actual.get(name, "notrun")
        wanted = test["expect"][args.profile]
        test_results.append(
            {
                "name": name,
                "classification": test["classification"],
                "adaptation": test.get("adaptation"),
                "expected": wanted,
                "actual": got,
                "matches": got != "notrun" and outcome_class(got) == outcome_class(wanted),
                "tags": test.get("tags", []),
                "requirements": test.get("requirements", []),
                "note": test.get("note", ""),
            }
        )

    ledger_counts = collections.Counter(value[0] for value in inventory.values())
    passing = sum(test["actual"] == "pass" for test in test_results)
    known_failures = sum(test["actual"] in {"fail", "xfail"} for test in test_results)
    skipped = sum(test["actual"] == "skip" for test in test_results)
    applicable = len(test_results)
    report = {
        "schema": 1,
        "upstream_repository": upstream["repository"],
        "upstream_commit": upstream["commit"],
        "profile": args.profile,
        "profile_args": profile.get("args", []),
        "platform": platform_name(),
        "run_as": running_as(),
        "applicable": applicable,
        "passing": passing,
        "known_failures": known_failures,
        "skipped": skipped,
        "adapted": sum(test["classification"] == "adapted" for test in test_results),
        "environment_excluded": [test["name"] for test in environment_excluded],
        "score_percent": (passing * 100.0 / applicable) if applicable else 0.0,
        "ledger": {key: ledger_counts[key] for key in sorted(VALID_CLASSES)},
        "tests": test_results,
        "runner_exit_code": returncode,
    }
    reports = cache / "reports"
    reports.mkdir(exist_ok=True)
    report_stem = args.profile + (f"-{args.report_label}" if args.report_label else "")
    report_json = reports / f"{report_stem}.json"
    report_md = reports / f"{report_stem}.md"
    report_log = reports / f"{report_stem}.log"
    report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = markdown_report(report)
    report_md.write_text(summary)
    report_log.write_text(log)
    print("\n" + summary, flush=True)
    if github_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(github_summary).open("a") as handle:
            handle.write(summary)

    if not args.preserve_scratch:
        shutil.rmtree(run_dir, ignore_errors=True)
    mismatches = [test for test in test_results if not test["matches"]]
    return 1 if returncode or mismatches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CompatError, subprocess.CalledProcessError) as error:
        print(f"rsync-compat: {error}", file=sys.stderr)
        raise SystemExit(2)
