"""A server copies files from the laptop (`syq cp --from @laptop`), approved there.

Fixtures live in disposable directories under the receiving root; the copy
writes only into a fresh server directory.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


receive_root = Path("/tmp/syq-real-ssh-receive")
fixture = receive_root / "send-fixture"
(fixture / ".kube" / "cache").mkdir(parents=True)
(fixture / ".kube" / "config").write_bytes(b"clusters: []\n")
large = os.urandom(6 * 1024 * 1024)
(fixture / ".kube" / "cache" / "large").write_bytes(large)
(fixture / ".kube" / "link").symlink_to("config")
(fixture / "kube-link").symlink_to(".kube")
outside = Path(tempfile.mkdtemp(prefix="syq-send-outside-"))
(outside / "secret").write_bytes(b"secret")
(fixture / "escape").symlink_to(outside)
(fixture / "sub").mkdir()
(fixture / "sub" / "sibling").symlink_to("../.kube")
before = sorted(str(path.relative_to(fixture)) for path in fixture.rglob("*"))
server = run("ssh", "source", "mktemp -d /tmp/syq-send-destination.XXXXXX").strip()


def server_command(arguments, tcp):
    # No agent and no key on the server: only the laptop's approval lets this work.
    return ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && exec env '
            + ("SYQ_TEST_REQUIRE_TCP=1 " if tcp else "") + shlex.join(arguments))


def copy(sources, into, *, allow=True, success=True, tcp=True, extra=(), binary="syq",
         prompt=True):
    arguments = [binary, "cp", "--from", "@laptop", *sources, "--into", server + "/" + into,
                 "--performance-tuning", "workers=2", *extra]
    if not tcp:
        arguments.append("--no-tcp")
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", server_command(arguments, tcp)],
                                   stdout=output, stderr=output, start_new_session=True)
        try:
            request = None
            if prompt:
                pending = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                         "--wait", "--timeout", "15"))
                assert len(pending) == 1, pending
                request = pending[0]
                assert request["kind"] == "send", request
                assert "leave this machine" in request["permission"], request
                assert "destination" not in request, request
                run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
            deadline = time.monotonic() + 60
            while True:
                try:
                    code = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    print("Waiting for copy from the laptop:", into, flush=True)
                    assert time.monotonic() < deadline, "copy exceeded fixture deadline"
            output.seek(0)
            text = output.read().decode(errors="replace")
            assert (code == 0) == success, (code, text)
            assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
            return request, text
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def server_digest(path):
    return run("ssh", "source", "sha256sum " + shlex.quote(server + "/" + path)).split()[0]


print("case: sending asks, even where receiving is approved automatically", flush=True)
run("syq", "persist", "receive", "on", "--auto-approve-root", str(receive_root), "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
request, _ = copy(["send-fixture/.kube"], "denied", allow=False, success=False)
assert request["paths"][0].startswith(str(fixture / ".kube") + " "), request
run("ssh", "source", "test ! -e " + shlex.quote(server + "/denied/.kube"))

for tcp in [True, False]:
    label = "tcp" if tcp else "ssh"
    print("case: an approved copy from the laptop over", label, flush=True)
    copy(["send-fixture/.kube"], label, tcp=tcp)
    assert server_digest(label + "/.kube/cache/large") == hashlib.sha256(large).hexdigest()
    assert run("ssh", "source", "cat " + shlex.quote(server + "/" + label + "/.kube/config")) \
        == "clusters: []\n"
    assert run("ssh", "source", "readlink " + shlex.quote(server + "/" + label + "/.kube/link")) \
        .strip() == "config"

print("case: another server build hands the copy to the laptop's helper", flush=True)
copy(["send-fixture/.kube/config"], "other-build", binary="syq-other-build")
assert run("ssh", "source", "cat " + shlex.quote(server + "/other-build/config")) == "clusters: []\n"

print("case: a named symlink needs --follow-src or --src-non-dir", flush=True)
_, text = copy(["send-fixture/kube-link"], "link-refused", success=False)
assert "--follow-src" in text, text
copy(["--src-non-dir", "send-fixture/kube-link"], "link-kept")
assert run("ssh", "source", "readlink " + shlex.quote(server + "/link-kept/kube-link")) \
    .strip() == ".kube"

print("case: a mapping renames files read from the laptop", flush=True)
mapping = server + "-mapping.ndjson"
run("ssh", "source", "printf '%s\\n' " + shlex.quote(json.dumps(
    {"src": {"encoding": "utf-8", "value": ".kube/config"}, "dst": {"encoding": "utf-8", "value": "renamed/config"}}))
    + " > " + shlex.quote(mapping))
request, _ = copy(["--mapping", mapping, "-C", "send-fixture"], "mapped")
assert request["paths"][0].startswith(str(fixture) + " "), request
assert run("ssh", "source", "cat " + shlex.quote(server + "/mapped/renamed/config")) \
    == "clusters: []\n"
run("ssh", "source", "test ! -e " + shlex.quote(server + "/mapped/renamed/cache"))

print("case: reads outside the receiving root are refused without asking", flush=True)
for path in [str(outside / "secret"), "../" + outside.name + "/secret"]:
    _, text = copy([path], "outside", success=False, prompt=False)
    assert "inside its receiving root" in text, text
run("ssh", "source", "test ! -e " + shlex.quote(server + "/outside/secret"))

print("case: symlinks can't lead reads out of the receiving root", flush=True)
for base in [["--root", "send-fixture/escape"], ["-C", "send-fixture/escape"], []]:
    for follow in [[], ["--follow-src"]]:
        named = ["secret"] if base else ["send-fixture/escape/secret"]
        _, text = copy([*base, *follow, "--src-non-dir", *named], "escaped", success=False)
        assert any(reason in text for reason in [
            "refusing to follow symlink", "outside its root",
            "outside its confined root"]), (base, follow, text)
        run("ssh", "source", "test ! -e " + shlex.quote(server + "/escaped/secret"))

print("case: the command's own --root still confines inside the receiving root", flush=True)
_, text = copy(["--root", "send-fixture/sub", "--follow-src", "--src-non-dir", "sibling/config"],
               "sibling", success=False)
assert "outside its confined root" in text, text
copy(["-C", "send-fixture/sub", "--follow-src", "--src-non-dir", "sibling/config"], "sibling")
assert run("ssh", "source", "cat " + shlex.quote(server + "/sibling/config")) == "clusters: []\n"

print("case: ~/ paths read the laptop's home and show where", flush=True)
token = Path.home() / "syq-send-token"
token.write_bytes(b"real\n")
cwd = Path(tempfile.mkdtemp(prefix="syq-send-cwd-"))
(cwd / "~").mkdir()
(cwd / "~" / "syq-send-token").write_bytes(b"decoy\n")
run("syq", "persist", "receive", "on", "--no-root", "--cwd", str(cwd), "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
request, _ = copy(["~/syq-send-token"], "home")
assert request["paths"][0].startswith(str(token) + " "), request
assert run("ssh", "source", "cat " + shlex.quote(server + "/home/syq-send-token")) == "real\n"
run("syq", "persist", "receive", "on", "--root", str(receive_root), "--auto-cwd", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
_, text = copy(["~/syq-send-token"], "home-rooted", success=False, prompt=False)
assert "inside its receiving root" in text and str(receive_root) not in text, text
token.unlink()

# Nothing changed on the laptop.
assert sorted(str(path.relative_to(fixture)) for path in fixture.rglob("*")) == before
run("ssh", "source", "rm -rf " + shlex.quote(server) + " " + shlex.quote(mapping))
