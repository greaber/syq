"""An ordinary SSH login reaches a local provider without agent forwarding."""
import contextlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


NATIVE_PATH = "PATH=/usr/bin:/bin:/usr/local/bin"
TARGET = "provider-destination"


def run(*args, data=None, success=True, env=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True,
                            timeout=40, env=env)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(host, *args, **kwargs):
    return run("ssh", host, shlex.join(args), **kwargs)


def wait_for(description, predicate, timeout=15):
    deadline, progress = time.monotonic() + timeout, time.monotonic() + 3
    observed = None
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        if time.monotonic() >= progress:
            print("Waiting for", description, "last state:", observed, flush=True)
            progress += 3
        time.sleep(.05)
    raise AssertionError((description, "timed out; last state", observed))


def terminate(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def cleanup_actions(actions):
    original_failure = sys.exc_info()[1]
    failures = []
    for description, action in actions:
        try:
            action()
        except Exception as error:
            failures.append((description, repr(error)))
    if failures:
        print("Provider fixture cleanup failures:", failures, flush=True)
        if original_failure is None:
            raise AssertionError(failures)


def no_pending(environment):
    assert json.loads(run("syq", "persist", "receive", "pending", "--json", env=environment)) == []


@contextlib.contextmanager
def provider_sshd(root, public_key, provider_environment, unix_forwarding="local"):
    """Only this disposable listener permits local Unix forwarding.

    The normal runner/source sshd stays remote-only; destination forwarding
    remains disabled. Provider login uses an independent key; the jump case
    also admits the lab agent's public key on this disposable listener.
    """
    key = root / "host_key"
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    authorized = root / "authorized_keys"
    authorized.write_text(public_key)
    authorized.chmod(0o600)
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 0))
        port = listener.getsockname()[1]
    config = root / "sshd_config"
    max_sessions = 1 if os.environ.get("SYQ_REAL_SSH_PROFILE") == "max-sessions-1" else 10
    config.write_text("\n".join([
        "Port " + str(port), "ListenAddress 0.0.0.0", "AddressFamily inet",
        "HostKey " + str(key), "PidFile " + str(root / "sshd.pid"),
        "AuthorizedKeysFile " + str(authorized), "StrictModes yes", "AllowUsers syq",
        "AuthenticationMethods publickey", "PubkeyAuthentication yes",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "UseDNS no", "AllowAgentForwarding no",
        # OpenSSH 9.2 initializes shared local-forward permissions from the
        # TCP flag; denying it also denies Unix socket connections.
        "AllowTcpForwarding local", "AllowStreamLocalForwarding " + unix_forwarding,
        "X11Forwarding no", "PermitTTY no",
        "MaxSessions " + str(max_sessions), "LogLevel VERBOSE",
        # OpenSSH uses only the first SetEnv directive. Both variables must
        # be assignments in that one directive.
        "SetEnv XDG_CONFIG_HOME=" + provider_environment["XDG_CONFIG_HOME"]
        + " XDG_RUNTIME_DIR=" + provider_environment["XDG_RUNTIME_DIR"], "",
    ]))
    environment = provider_environment.copy()
    # The service inherits the local agent. Incoming provider logins do not.
    environment.pop("SSH_AUTH_SOCK", None)
    environment.pop("SSH_AGENT_PID", None)
    effective = run("/usr/sbin/sshd", "-T", "-f", str(config), env=environment)
    policy = dict(line.split(" ", 1) for line in effective.splitlines() if " " in line)
    for name, expected in {"allowtcpforwarding": "local", "allowstreamlocalforwarding": unix_forwarding,
                           "allowagentforwarding": "no", "disableforwarding": "no"}.items():
        assert policy.get(name) == expected, (name, policy.get(name), expected)
    with (root / "sshd.log").open("w+") as log:
        process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   env=environment, start_new_session=True)
        def ready():
            assert process.poll() is None, "fixture provider sshd exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return True
            except OSError:
                return False
        try:
            wait_for("fixture provider SSH listener", ready)
            yield port, key.with_suffix(".pub").read_text()
        except BaseException:
            log.seek(0)
            print(log.read(), flush=True)
            raise
        finally:
            cleanup_actions([
                ("provider persistence", lambda: run("syq", "persist", "off", env=provider_environment)),
                ("fixture provider sshd", lambda: terminate(process)),
            ])


def main():
    source_root = remote("source", "mktemp", "-d", "/tmp/sp.XXXXXX").strip()
    destination_root = remote("destination", "mktemp", "-d", "/tmp/syq-provider.XXXXXX").strip()
    source_environment = ["env", NATIVE_PATH, "XDG_CONFIG_HOME=" + source_root + "/c",
                          "XDG_RUNTIME_DIR=" + source_root + "/r"]
    source_config_changed = False
    scopes = []
    provider_environment = None
    config = Path.home() / ".ssh/config"
    original_config = config.read_bytes()

    def source(*args, **kwargs):
        return remote("source", *source_environment, *args, **kwargs)

    def execute(*args, ask=False, allow=True, targets=None):
        command = shlex.join([*source_environment, "syq", *args])
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(["ssh", "source", command], stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=output, start_new_session=True)
            try:
                approvals = list(targets or [({"user": "syq", "host": "destination", "port": 22}, "destination")]) if ask else []
                while approvals:
                    items = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                           "--wait", "--timeout", "15", env=provider_environment))
                    assert len(items) == 1, items
                    item = items[0]
                    assert item["kind"] == "provider_ssh", item
                    assert "account" not in item, item
                    permission = item["provider_account"]
                    assert "source" not in permission, permission
                    assert permission["provider"]["user"] == "syq", permission
                    destination = permission["destination"]
                    endpoint = destination["endpoint"]
                    expected = next((value for value in approvals if value[0] == endpoint), None)
                    assert expected is not None, (endpoint, approvals)
                    assert destination["trusted_host"] == expected[1], item
                    assert item["destination"] == endpoint["user"] + "@" + expected[1], item
                    approvals.remove(expected)
                    assert "commands and copies" in item["permission"], item
                    run("syq", "persist", "receive", "approve" if allow else "deny", item["id"],
                        env=provider_environment)
                deadline = time.monotonic() + 40
                while True:
                    try:
                        status = process.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        print("Waiting for provider-authorized operation", flush=True)
                        assert time.monotonic() < deadline, "provider operation exceeded its deadline"
                output.seek(0)
                text = output.read().decode(errors="replace")
                assert (status == 0) == allow, (args, status, text)
                no_pending(provider_environment)
                return text
            except BaseException:
                output.seek(0)
                print(output.read().decode(errors="replace"), flush=True)
                raise
            finally:
                cleanup_actions([("requester client", lambda: terminate(process))])

    try:
        source("mkdir", "-m", "700", source_root + "/r", source_root + "/c")
        source("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", source_root + "/provider_key")
        public_key = source("cat", source_root + "/provider_key.pub")
        destination_key = run("ssh-keygen", "-y", "-f", str(Path.home() / ".ssh/id_ed25519"))
        destination_identity = source_root + "/destination.pub"
        source("python3", "-c", "from pathlib import Path; import sys; "
               "Path(sys.argv[1]).write_text(sys.stdin.read())", destination_identity, data=destination_key)
        remote("source", "sh", "-c", 'test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519')
        # This credential cannot authenticate to the destination, even when its
        # hostname and host key are supplied directly.
        source("/usr/bin/ssh", "-F", "/dev/null", "-a", "-o", "BatchMode=yes",
               "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null", "-i", source_root + "/provider_key",
               "syq@destination", "true", success=False)
        # sshd StrictModes validates every ancestor of authorized_keys. Keep
        # its files below the private account home, not world-writable /tmp.
        with tempfile.TemporaryDirectory(prefix="syq-provider-", dir=Path.home() / ".ssh") as temporary:
            root = Path(temporary)
            for directory in (root / "config", root / "runtime"):
                directory.mkdir(mode=0o700)
            provider_environment = os.environ.copy()
            provider_environment.update(XDG_CONFIG_HOME=str(root / "config"),
                                        XDG_RUNTIME_DIR=str(root / "runtime"))
            with provider_sshd(root, public_key + destination_key, provider_environment) as (port, host_key):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                    route.connect((socket.gethostbyname("source"), 22))
                    address = route.getsockname()[0]
                source("python3", "-c", "from pathlib import Path; import sys; "
                       "Path(sys.argv[1]).write_text(sys.stdin.read())", source_root + "/known_hosts",
                       data="[{}]:{} {}".format(address, port, host_key))
                prefix = ("Host provider\n  HostName {}\n  Port {}\n  User syq\n"
                          "  IdentityFile {}\n  IdentityAgent none\n  IdentitiesOnly yes\n"
                          "  StreamLocalBindMask 0000\n"
                          "  BatchMode yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {}\n"
                          "  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys no\n"
                          "Host {}\n  HostName destination\n  User syq\n  Port 22\n"
                          "  IdentityFile {}\n  IdentitiesOnly yes\n  BatchMode yes\n\n").format(
                              address, port, source_root + "/provider_key", source_root + "/known_hosts",
                              TARGET, destination_identity)
                source("python3", "-c", "from pathlib import Path; import shutil,sys; "
                       "p=Path.home()/'.ssh/config'; backup=Path(sys.argv[1]); "
                       "shutil.copy2(p,backup) if p.exists() else None; "
                       "old=p.read_bytes() if p.exists() else b''; "
                       "p.write_bytes(sys.stdin.buffer.read()+old); p.chmod(0o600)",
                       source_root + "/config.saved", data=prefix)
                source_config_changed = True
                # Only provider trust applies; its alias route and login must
                # not override the requester's selected destination account.
                config.write_bytes(("Host {}\n  HostName source\n  User longhome\n  HostKeyAlias destination\n"
                                    "  IdentityFile /home/syq/.ssh/id_ed25519\n  IdentitiesOnly yes\n"
                                    "  BatchMode yes\n  StrictHostKeyChecking yes\n"
                                    "  UserKnownHostsFile /home/syq/.ssh/known_hosts\n"
                                    "  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys no\n\n".format(TARGET)).encode()
                                   + original_config)
                probe = shlex.join(["python3", "-c", "import json,os; print(json.dumps({name: os.environ.get(name) "
                                    "for name in ['XDG_CONFIG_HOME', 'XDG_RUNTIME_DIR', 'SSH_AUTH_SOCK']}))"])
                observed = json.loads(source("/usr/bin/ssh", "-a", "provider", probe))
                assert observed == {"XDG_CONFIG_HOME": provider_environment["XDG_CONFIG_HOME"],
                                    "XDG_RUNTIME_DIR": provider_environment["XDG_RUNTIME_DIR"],
                                    "SSH_AUTH_SOCK": None}, observed
                run("syq", "persist", "receive", "on", "--notify", "off", env=provider_environment)

                print("case: a lazy provider login requests destination-account approval", flush=True)
                execute("ssh", "--auth-from", "provider", TARGET, "--", "true", ask=True, allow=False)
                execute("ssh", "--auth-from", "provider", TARGET, "--", "printf PROVIDER_OK", ask=True)
                assert "PROVIDER_OK" in execute("ssh", "--auth-from", "provider", TARGET,
                                               "--", "printf PROVIDER_OK")

                print("case: saved provider choices support terse commands and copies", flush=True)
                source("syq", "persist", "auth-from", "provider", "--for", TARGET)
                assert "SAVED_OK" in execute("ssh", TARGET, "--", "printf SAVED_OK")
                payload = "provider-copy-data\n" * 131072
                source("python3", "-c", "from pathlib import Path; import sys; "
                       "Path(sys.argv[1]).write_text(sys.stdin.read())", source_root + "/payload", data=payload)
                # The file exceeds the small-file control path. Both
                # directions need independent authenticated data sessions,
                # including in the MaxSessions=1 profile, with no new prompt.
                execute("cp", source_root + "/payload", "--to", TARGET, "--as", destination_root + "/copied",
                        "--no-tcp", "--performance-tuning", "workers=2", "--no-progress")
                assert remote("destination", "cat", destination_root + "/copied") == payload
                execute("cp", "--from", TARGET, destination_root + "/copied", "--as", source_root + "/roundtrip",
                        "--no-tcp", "--performance-tuning", "workers=2", "--no-progress")
                assert source("cat", source_root + "/roundtrip") == payload

                print("case: requester scopes keep provider preferences and connections separate", flush=True)
                scope = source("syq", "persist", "on", "--ephemeral").strip()
                scopes.append(scope)
                execute("ssh", "--pscope", scope, TARGET, "--", "true", allow=False)
                source("syq", "persist", "--pscope", scope, "auth-from", "provider", "--for", TARGET)
                execute("ssh", "--pscope", scope, TARGET, "--", "true", ask=True)
                source("syq", "persist", "--pscope", scope, "off")
                scopes.remove(scope)
                source("test", "!", "-e", scope)
                assert "GLOBAL_OK" in execute("ssh", TARGET, "--", "printf GLOBAL_OK")
                print("case: ProxyJump approves each account and carries the selected route", flush=True)
                jump, via_jump, via_command = "provider-jump", "provider-via-jump", "provider-via-command"
                trust = "provider-jump-trust"
                jump_config = ("Host " + jump + "\n  HostName " + address + "\n  Port " + str(port)
                               + "\n  User syq\n  HostKeyAlias " + trust + "\n  IdentityFile "
                               + destination_identity + "\n  IdentitiesOnly yes\n  BatchMode yes\n"
                               + "Host " + via_jump + "\n  HostName destination\n  User syq\n  Port 22\n"
                               + "  IdentityFile " + destination_identity + "\n  IdentitiesOnly yes\n  ProxyJump " + jump + "\n")
                trust_file = root / "jump-known-hosts"
                trust_file.write_text("[{}]:{} {}".format(address, port, host_key))
                trust_config = ("Host " + trust + "\n  HostName " + address + "\n  Port " + str(port)
                                + "\n  UserKnownHostsFile " + str(trust_file) + "\n  GlobalKnownHostsFile /dev/null\n"
                                + "Host " + via_jump + " " + via_command
                                + "\n  HostName destination\n  HostKeyAlias destination\n"
                                + "  UserKnownHostsFile /home/syq/.ssh/known_hosts\n  GlobalKnownHostsFile /dev/null\n")
                config.write_bytes(trust_config.encode() + config.read_bytes())
                source("python3", "-c", "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
                       "p.write_text(sys.stdin.read()+p.read_text())", data=jump_config)
                jump_scope = source("syq", "persist", "on", "--ephemeral").strip()
                scopes.append(jump_scope)
                route_command = "printf 'ROUTE=%s\\n' \"$SSH_CONNECTION\""
                route = execute("ssh", "--pscope", jump_scope, "--auth-from", "provider", via_jump,
                                "--", route_command, ask=True,
                                targets=[({"user": "syq", "host": address, "port": port}, "[{}]:{}".format(address, port)),
                                         ({"user": "syq", "host": "destination", "port": 22}, "destination")])
                assert next(line for line in route.splitlines() if line.startswith("ROUTE=")).split()[0] == "ROUTE=" + address, route
                rows = json.loads(source("syq", "persist", "status", "--pscope", jump_scope, "--json"))["authorized_ssh"]
                assert {(row["endpoint"]["host"], row["endpoint"]["port"]) for row in rows if row["connected"]} == {
                    (address, port), ("destination", 22)}, rows
                assert "JUMP_WARM" in execute("ssh", "--pscope", jump_scope, "--auth-from", "provider",
                                             via_jump, "--", "printf JUMP_WARM")
                source("syq", "persist", "--pscope", jump_scope, "off")
                scopes.remove(jump_scope)

                print("case: arbitrary ProxyCommand uses its own credential and no provider agent", flush=True)
                proxy_script, proxy_marker = source_root + "/proxy", source_root + "/proxy-used"
                proxy = ("#!/bin/sh\nset -eu\ntest -z \"${SSH_AUTH_SOCK:-}\"\n"
                         + "printf 'local-key-only\\n' >> " + shlex.quote(proxy_marker) + "\nexec "
                         + shlex.join(["/usr/bin/ssh", "-F", "/dev/null", "-a", "-o", "IdentityAgent=none",
                             "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                             "-o", "UserKnownHostsFile=" + source_root + "/known_hosts", "-o", "GlobalKnownHostsFile=/dev/null",
                             "-i", source_root + "/provider_key", "-p", str(port), "-l", "syq"])
                         + ' -W "$1:$2" ' + shlex.quote(address) + "\n")
                source("python3", "-c", "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
                       "p.write_text(sys.stdin.read()); p.chmod(0o700)", proxy_script, data=proxy)
                proxy_config = ("Host " + via_command + "\n  HostName destination\n  User syq\n  Port 22\n"
                                + "  IdentityFile " + destination_identity + "\n  IdentitiesOnly yes\n"
                                + "  ProxyCommand " + proxy_script + " %h %p\n")
                source("python3", "-c", "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
                       "p.write_text(sys.stdin.read()+p.read_text())", data=proxy_config)
                proxy_scope = source("syq", "persist", "on", "--ephemeral").strip()
                scopes.append(proxy_scope)
                route = execute("ssh", "--pscope", proxy_scope, "--auth-from", "provider", via_command,
                                "--", route_command, ask=True)
                assert next(line for line in route.splitlines() if line.startswith("ROUTE=")).split()[0] == "ROUTE=" + address, route
                assert source("cat", proxy_marker) == "local-key-only\n"
                rows = json.loads(source("syq", "persist", "status", "--pscope", proxy_scope, "--json"))["authorized_ssh"]
                assert len(rows) == 1 and rows[0]["endpoint"]["host"] == "destination", rows
                source("syq", "persist", "--pscope", proxy_scope, "off")
                scopes.remove(proxy_scope)
                source("syq", "persist", "off")
                no_pending(provider_environment)

                print("case: denied Unix forwarding never publishes a ready provider", flush=True)
                denied_root = root / "denied"
                denied_root.mkdir(mode=0o700)
                with provider_sshd(denied_root, public_key, provider_environment,
                                   unix_forwarding="no") as (denied_port, denied_key):
                    denied_hosts = source_root + "/denied-known-hosts"
                    source("python3", "-c", "from pathlib import Path; import sys; "
                           "Path(sys.argv[1]).write_text(sys.stdin.read())", denied_hosts,
                           data="[{}]:{} {}".format(address, denied_port, denied_key))
                    denied_config = ("Host denied-provider\n  HostName {}\n  Port {}\n  User syq\n"
                                     "  IdentityFile {}\n  IdentityAgent none\n  IdentitiesOnly yes\n"
                                     "  BatchMode yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {}\n"
                                     "  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys no\n").format(
                                         address, denied_port, source_root + "/provider_key", denied_hosts)
                    source("python3", "-c", "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
                           "p.write_text(sys.stdin.read()+p.read_text())", data=denied_config)
                    denied_scope = source("syq", "persist", "on", "--ephemeral").strip()
                    scopes.append(denied_scope)
                    text = execute("persist", "connect", TARGET, "--pscope", denied_scope,
                                   "--auth-from", "denied-provider", allow=False)
                    assert "sshd permits local forwarding" in text, text
                    # A local -O forward listener alone is not readiness. In
                    # the old flow the later Resolve failed but the keeper's
                    # published ticket and provider record stayed reusable.
                    records = json.loads(source("python3", "-c",
                        "from pathlib import Path; import json,sys; "
                        "print(json.dumps([p.name for p in (Path(sys.argv[1])/'provider-links-v1').glob('*.json')]))",
                        denied_scope))
                    assert records == [], records
                    source("syq", "persist", "--pscope", denied_scope, "off")
                    scopes.remove(denied_scope)
                print("Ordinary SSH provider passed", flush=True)
    finally:
        actions = [("requester scope", lambda scope=scope: source("syq", "persist", "--pscope", scope, "off"))
                   for scope in scopes]
        actions.extend([
            ("requester persistence", lambda: source("syq", "persist", "off")),
            ("provider SSH config", lambda: config.write_bytes(original_config)),
        ])
        if source_config_changed:
            actions.append(("requester SSH config", lambda: source("python3", "-c",
                "from pathlib import Path; import shutil,sys; "
                "p=Path.home()/'.ssh/config'; backup=Path(sys.argv[1]); "
                "shutil.copy2(backup,p) if backup.exists() else p.unlink()", source_root + "/config.saved")))
        actions.extend([
            ("requester files", lambda: remote("source", "rm", "-rf", "--", source_root)),
            ("destination files", lambda: remote("destination", "rm", "-rf", "--", destination_root)),
        ])
        cleanup_actions(actions)


main()
