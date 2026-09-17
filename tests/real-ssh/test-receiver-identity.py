#!/usr/bin/env python3
"""Exercise offline ownership and explicit replacement in disposable accounts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*args, env=None, success=True):
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", flush=True)
    assert (result.returncode == 0) == success, (args, result.returncode)
    return result.stdout


# The scenario runner has just stopped its original laptop connection.
original_key = Path.home() / ".syq-receiver-identity/identity_ed25519"
key_before = original_key.read_bytes()
owner_before = run("ssh", "source", "cat ~/.syq-destinations-v3/laptop.owner")
listing = run("ssh", "source", "syq persist destinations list")
assert "@laptop\toffline" in listing, listing
with tempfile.TemporaryDirectory(prefix="syq-other-receiver-") as directory:
    env = dict(os.environ, HOME=directory,
               XDG_CONFIG_HOME=directory + "/config", XDG_RUNTIME_DIR=directory + "/runtime")
    Path(env["XDG_RUNTIME_DIR"]).mkdir(mode=0o700)
    try:
        run("syq", "persist", "receive", "on", "--name", "laptop", "--root", directory, env=env)
        run("syq", "persist", "connect", "source", "--timeout", "15", env=env, success=False)
        state = json.loads(run("syq", "persist", "receive", "status", "--json", env=env))
        assert any("different receiver" in (c["connection"].get("error") or "")
                   for c in state["connections"]), state
        assert run("ssh", "source", "cat ~/.syq-destinations-v3/laptop.owner") == owner_before
        run("ssh", "source", "syq persist destinations forget laptop")
        run("syq", "persist", "connect", "source", "--timeout", "15", env=env)
        run("ssh", "source", "syq persist destinations wait laptop --timeout 5")
        # Incoming copies cannot overwrite the identity, including under a
        # test-specific HOME rather than the account's passwd home directory.
        receiver_key = Path(directory) / ".syq-receiver-identity/identity_ed25519"
        receiver_key_before = receiver_key.read_bytes()
        run("syq", "persist", "receive", "on", "--name", "laptop", "--approve", "always", env=env)
        run("syq", "persist", "receive", "wait", "source", "--timeout", "15", env=env)
        run("ssh", "source", "syq cp /tmp/syq-real-ssh/return-source/message.txt "
            "--to @laptop --as .syq-receiver-identity/identity_ed25519", success=False)
        assert receiver_key.read_bytes() == receiver_key_before
        owner_after = run("ssh", "source", "cat ~/.syq-destinations-v3/laptop.owner")
        assert owner_before != owner_after
        run("ssh", "source", "syq persist destinations forget laptop", success=False)
    finally:
        run("syq", "persist", "off", env=env)
    run("ssh", "source", "syq persist destinations forget laptop")
assert original_key.read_bytes() == key_before
# Reusing the original installation after a service restart keeps its identity.
run("syq", "persist", "connect", "source")
assert run("ssh", "source", "cat ~/.syq-destinations-v3/laptop.owner") == owner_before
run("syq", "persist", "off")
