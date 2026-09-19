"""Check receiving preferences against an unchanged released v0.6.0 binary."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--old", required=True, type=Path)
parser.add_argument("--candidate", required=True, type=Path)
options = parser.parse_args()
old, candidate = options.old.resolve(), options.candidate.resolve()
assert subprocess.check_output([old, "--version"], text=True).strip() == "syq 0.6.0"

with tempfile.TemporaryDirectory(prefix="syq-policy-compat-") as temporary:
    home = Path(temporary)
    inbox = home / "inbox"
    inbox.mkdir()
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / "config"),
               XDG_RUNTIME_DIR=str(home / "runtime"), SYQ_NO_UPDATE_CHECK="1")

    def run(binary, *args, success=True):
        result = subprocess.run([binary, "persist", "receive", *args], env=env,
                                capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == success, (args, result)
        return result

    run(old, "on", "--name", "inbox", "--root", str(inbox), "--approve", "always",
        "--notify", "off", "--max-entries", "123")
    path = home / "config/syq/receive.json"
    original = path.read_bytes()
    assert json.loads(original)["version"] == 4
    upgraded = json.loads(run(candidate, "status", "--json").stdout)["settings"]
    assert upgraded["cwd"] == str(inbox)
    assert upgraded["cwd_explicit"] is True
    assert upgraded["root"] == str(inbox)
    assert upgraded["auto_approve_root"] is None
    assert upgraded["servers"] == []
    assert upgraded["max_entries"] == 123
    assert "approval" not in upgraded
    assert path.read_bytes() == original  # Read-only status does not migrate on disk.
    run(candidate, "on", "--auto-approve-root", str(inbox), "--server", "work")
    saved = path.read_bytes()
    assert json.loads(saved)["version"] == 5
    for args in [("status", "--json"), ("on", "--approve", "always")]:
        refused = run(old, *args, success=False)
        assert "unsupported receive preferences version" in refused.stderr
        assert path.read_bytes() == saved
    current = json.loads(run(candidate, "status", "--json").stdout)["settings"]
    assert current["auto_approve_root"] == str(inbox)
    assert current["servers"] == ["work"]

print("v0.6.0 preference migration and downgrade rejection passed")
