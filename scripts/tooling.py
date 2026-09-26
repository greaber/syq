"""Helpers shared by the repository's Python tooling (standard library only)."""
import hashlib
import json
import re
import signal
import subprocess
import sys
import tomllib


class ToolError(Exception):
    """A failure to report as `error: MESSAGE` before exiting with `status`."""

    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


def report_errors(main):
    """Run `main`, turning a ToolError into its message and exit status."""
    try:
        return main()
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return error.status


def output(*args, status=1, **kwargs):
    """stdout of a command that must succeed; its own stderr passes through.
    Pass stdout=None to let the command write to this process's stdout."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    sys.stdout.flush()
    completed = subprocess.run(list(args), text=True, **kwargs)
    if completed.returncode:
        raise ToolError(f"{' '.join(args[:3])} failed with exit status {completed.returncode}",
                        status)
    return completed.stdout


def json_output(*args, status=1, **kwargs):
    """The JSON printed by a command that must succeed, such as `gh api`."""
    text = output(*args, status=status, **kwargs)
    try:
        return json.loads(text)
    except ValueError:
        raise ToolError(f"{' '.join(args[:3])} printed invalid JSON", status) from None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def cargo_version(path):
    """The package version in a Cargo.toml."""
    try:
        with open(path, "rb") as source:
            return tomllib.load(source)["package"]["version"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ToolError(f"cannot read the package version from {path}: {error}") from None


def check_conclusion(check_runs, name):
    """The latest conclusion of the named GitHub check run: `missing` when
    there is none and `pending` while it is incomplete."""
    runs = check_runs.get("check_runs") if isinstance(check_runs, dict) else None
    if not isinstance(runs, list):
        raise ToolError("GitHub returned no check runs")
    runs = [run for run in runs if isinstance(run, dict) and run.get("name") == name]
    runs.sort(key=lambda run: (run.get("started_at") or run.get("completed_at") or "",
                               run.get("id") or 0))
    if not runs:
        return "missing"
    return runs[-1].get("conclusion") or "pending"


class ForwardSignals:
    """Run child commands one at a time and pass SIGINT, SIGTERM, and SIGHUP to
    the running child. Once that child ends, the interrupted script exits with
    128 plus the signal number, as a shell does; `shield()` lets its cleanup
    finish without further interruption."""

    SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

    def __init__(self):
        self.child = None
        self.received = None
        for signum in self.SIGNALS:
            signal.signal(signum, self._receive)

    def _receive(self, signum, frame):
        if self.received is None:
            self.received = signum
        if self.child is not None and self.child.poll() is None:
            self.child.send_signal(signum)

    def check(self):
        if self.received is not None:
            raise SystemExit(128 + self.received)

    def run(self, *args, capture=False, stop=True, **kwargs):
        """Run a command and return (exit status, captured stdout or None).
        With stop=False, a signal during the command is left for the caller's
        next `check()`, so it can record what the command created first."""
        self.check()
        sys.stdout.flush()
        self.child = subprocess.Popen(list(args), stdout=subprocess.PIPE if capture else None,
                                      text=True, **kwargs)
        # A signal that arrived while the child was starting found no child
        # to forward to; pass it on now instead of letting the child run on.
        if self.received is not None:
            self.child.send_signal(self.received)
        try:
            captured, _ = self.child.communicate()
        finally:
            status = self.child.wait()
            self.child = None
        if stop:
            self.check()
        return status, captured

    def shield(self):
        for signum in self.SIGNALS:
            signal.signal(signum, signal.SIG_IGN)


def load_release_manifest(path):
    """A release manifest with string version, tag, and canonical repository."""
    try:
        with open(path, encoding="utf-8") as source:
            manifest = json.load(source)
    except (OSError, ValueError) as error:
        raise ToolError(f"cannot read release manifest {path}: {error}") from None
    if not isinstance(manifest, dict) or not all(
            isinstance(manifest.get(key), str) and manifest[key]
            for key in ("version", "tag", "repository")):
        raise ToolError(f"release manifest {path} lacks its version, tag, or repository")
    if manifest["repository"] != "https://github.com/greaber/syq":
        raise ToolError("unexpected repository")
    # Generated files quote these values; allow only version characters.
    if (not re.fullmatch(r"[0-9A-Za-z.+-]+", manifest["version"])
            or manifest["tag"] != "v" + manifest["version"]):
        raise ToolError(f"release manifest {path} has an invalid version or tag")
    return manifest
