#!/bin/sh
set -eu

home=/home/syq
config=$home/.ssh/config
known_hosts=$home/.ssh/known_hosts
private_key=$home/.ssh/id_ed25519
blocked_tcp_port=${SYQ_REAL_SSH_BLOCKED_TCP_PORT:?missing blocked TCP port}

cleanup() {
    rc=$?
    trap - EXIT INT TERM
    if [ -n "${return_copy_pid:-}" ]; then
        kill -TERM "$return_copy_pid" 2>/dev/null || true
        wait "$return_copy_pid" 2>/dev/null || true
    fi
    if [ -n "${upgrade_old_pid:-}" ]; then
        kill -TERM "$upgrade_old_pid" 2>/dev/null || true
        wait "$upgrade_old_pid" 2>/dev/null || true
    fi
    if [ -n "${upgrade_scope:-}" ]; then
        syq persist off --pscope "$upgrade_scope" >/dev/null 2>&1 || true
    fi
    if [ -n "${switch_scope:-}" ]; then
        syq persist off --pscope "$switch_scope" >/dev/null 2>&1 || true
    fi
    syq persist off >/dev/null 2>&1 || true
    if [ -n "${SSH_AGENT_PID:-}" ]; then
        ssh-agent -k >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"$config" <<'EOF'
Host source destination
    User syq
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    IdentitiesOnly yes
    IdentityFile /home/syq/.ssh/id_ed25519
    StrictHostKeyChecking yes
    UserKnownHostsFile /home/syq/.ssh/known_hosts
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    SendEnv SYQ_REAL_SSH_SENT_ENV
EOF
chmod 0600 "$config"

ssh-keyscan -T 5 -t ed25519 source destination >"$known_hosts"
test -s "$known_hosts"
chmod 0600 "$known_hosts"
host_key_count=$(awk '{ print $2, $3 }' "$known_hosts" | sort -u | wc -l | tr -d '[:space:]')
if [ "$host_key_count" -ne 2 ]; then
    echo "source and destination did not expose two distinct host keys" >&2
    exit 1
fi

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$private_key" >/dev/null

ssh source true
ssh destination true
ssh source 'test ! -e ~/.ssh/id_ed25519'
ssh destination 'test ! -e ~/.ssh/id_ed25519'
ssh destination 'install -d -m 0755 /tmp/syq-real-ssh'

case "${SYQ_REAL_SSH_SUITE:-core}" in
    core) ;;
    metadata)
        python3 /usr/local/libexec/syq-test-metadata.py
        exit 0
        ;;
    storage)
        python3 /usr/local/libexec/syq-test-storage-authorization.py
        exit 0
        ;;
    benchmark)
        sh /usr/local/libexec/syq-real-ssh-benchmark
        exit 0
        ;;
    *) echo 'unknown real-SSH suite' >&2; exit 2 ;;
esac

remote_manifest() {
    host=$1
    root=$2
    output=$3
    ssh "$host" sh -s -- "$root" >"$output" <<'EOF'
set -eu
cd "$1"
{
    find . -mindepth 1 -printf '%y %m %p -> %l\n'
    find . -type f -exec sha256sum {} +
} | LC_ALL=C sort
EOF
}

assert_same_tree() {
    source_host=$1
    source_root=$2
    destination_host=$3
    destination_root=$4
    label=$5
    source_manifest="/tmp/${label}-source.manifest"
    destination_manifest="/tmp/${label}-destination.manifest"
    # Endpoints have separate filesystems; collect both snapshots concurrently.
    remote_manifest "$source_host" "$source_root" "$source_manifest" &
    source_manifest_pid=$!
    remote_manifest "$destination_host" "$destination_root" "$destination_manifest" &
    destination_manifest_pid=$!
    manifest_status=0
    wait "$source_manifest_pid" || manifest_status=1
    wait "$destination_manifest_pid" || manifest_status=1
    [ "$manifest_status" -eq 0 ] || return 1
    diff -u "$source_manifest" "$destination_manifest"
}

assert_preview_counts() {
    python3 - "$1" "$2" "$3" <<'PYTHON'
import json, sys
from pathlib import Path
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
result = records[-1]
assert result['type'] == 'result' and result['status'] == 'success', records
assert result['dry_run'] and result['errors'] == 0, result
assert result['files_transferred'] == int(sys.argv[2]), result
assert result['files_unchanged'] == int(sys.argv[3]), result
assert result['symlinks_created'] == result['specials_created'] == 0, result
changes = [r for r in records if r['type'] == 'trace' and r['action'] == 'transfer_file' and 'bytes' in r]
assert len(changes) == int(sys.argv[2]), records
if changes:
    assert [(r['dst']['value'], r['reason']) for r in changes] == [('policy-new', 'destination_missing')], changes
PYTHON
}

make_tree() {
    host=$1
    root=$2
    marker=$3
    ssh "$host" sh -s -- "$root" "$marker" <<'EOF'
set -eu
root=$1
marker=$2
install -d -m 0750 "$root/subdir"
printf '%s\n' "$marker" >"$root/message.txt"
dd if=/dev/zero of="$root/subdir/chunks.bin" bs=1M count=3 status=none
chmod 0640 "$root/message.txt" "$root/subdir/chunks.bin"
ln -s message.txt "$root/link"
EOF
}

printf 'real-SSH environment: profile %s; %s; %s\n' \
    "${SYQ_REAL_SSH_PROFILE:-default}" "$(syq --build-identity)" "$(ssh -V 2>&1)"
# The suite exercises constrained agent forwarding, which docs/install.md
# supports from OpenSSH 8.9. Fail loudly if the image ever drifts below it.
ssh_release=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')
ssh_major=${ssh_release%% *}
ssh_minor=${ssh_release#* }
if [ -z "$ssh_release" ] || [ "$ssh_major" -lt 8 ] || { [ "$ssh_major" -eq 8 ] && [ "$ssh_minor" -lt 9 ]; }; then
    echo "real-SSH suite needs OpenSSH 8.9 or newer in the container image; found: $(ssh -V 2>&1)" >&2
    exit 1
fi

printf 'case: source build uploads itself over real SSH to empty binary stores\n'
printf 'development helper upload\n' > /tmp/dev-helper-upload.txt
identity=$(syq --build-identity)
for host in source destination; do
    ssh "$host" 'test ! -e "$HOME/.local/lib/syq" && test ! -e "$HOME/.cache/syq/helpers"'
    syq cp /tmp/dev-helper-upload.txt --to "$host" --into /tmp
    ssh "$host" 'cmp /tmp/dev-helper-upload.txt /dev/stdin' < /tmp/dev-helper-upload.txt
    # The helper went to the binary store, and nothing to the old cache.
    # shellcheck disable=SC2029
    ssh "$host" "cmp /usr/local/bin/syq \"\$HOME/.local/lib/syq/$identity/linux-\$(uname -m)/syq\" &&
        test ! -e \"\$HOME/.cache/syq/helpers\""
done
# The completion scenario expects to discover only its own endpoint.
syq completion cache clear >/dev/null

printf 'case: descriptor upload and download over real SSH\n'
python3 - <<'PY_DESCRIPTORS'
import subprocess
payload = bytes(range(256)) * 80000 + b'last\x00\xff'
controls = ["--integrity-checking", "transfer=md5",
            "--performance-tuning", "request-size=1M,pipeline-depth=8", "--stats", "-vv"]
path = "/tmp/syq-real-ssh/stream 'with spaces'"
# Fixed workers plus pacing give both workers time to carry payload. Verify the
# actual per-worker byte counters, not just that two connections were opened.
import re
for transport, extra in (("EncryptedTcp", []), ("Ssh", ["--no-tcp"])):
    parallel = [*controls, "--performance-tuning", "workers=2", "--resource-limits", "bandwidth=8M", *extra]
    policy = '--if-exists=keep' if transport == 'EncryptedTcp' else '--only-existing'
    upload = subprocess.run(['syq', 'cp', '--src-fd', '0', '--to', 'destination', '--as', path, policy, *parallel],
                            input=payload, capture_output=True, check=True, timeout=60)
    result = subprocess.run(['syq', 'cp', '--from', 'destination', path, '--as-fd', '1', *parallel],
                            capture_output=True, check=True, timeout=60)
    assert result.stdout == payload
    for response, action in ((upload, "sent"), (result, "read")):
        assert response.stderr.count(("ready (" + transport + ")").encode()) == 2, response.stderr
        counts = re.findall(rb"stream worker (\d+): " + action.encode() + rb" (\d+) bytes", response.stderr)
        assert len(counts) == 2 and all(int(n) > 0 for _, n in counts), response.stderr
        assert sum(int(n) for _, n in counts) == len(payload), response.stderr
result = subprocess.run(['syq', 'cp', '--src-fd', '0', '--to', 'destination', '--as-new', path],
                        input=b'no', capture_output=True, timeout=30)
assert result.returncode != 0, result.stderr
result = subprocess.run(['syq', 'cp', '--from', 'destination', '--root', '/tmp/syq-real-ssh',
                         "stream 'with spaces'", '--as-fd', '1'], capture_output=True, timeout=60)
assert result.returncode == 0 and result.stdout == payload, result.stderr
result = subprocess.run(['syq', 'cp', '--from', 'destination', '--root', '/tmp/syq-real-ssh',
                         '../dev-helper-upload.txt', '--as-fd', '1'], capture_output=True, timeout=30)
assert result.returncode != 0, result.stderr
# Empty EOF must publish an empty file rather than leave the previous object.
subprocess.run(['syq', 'cp', '--if-exists=update', '--src-fd', '0', '--to', 'destination', '--as-existing', path], input=b'', check=True, timeout=30)
result = subprocess.run(['syq', 'cp', '--from', 'destination', path, '--as-fd', '1'], stdout=subprocess.PIPE, check=True, timeout=30)
assert result.stdout == b''
subprocess.run(['bash', '-c',
                'syq cp --if-exists=update --src <(printf "local producer") --to destination --as "$1"',
                'stream-test', path], check=True, timeout=30)
result = subprocess.run(['syq', 'cp', '--from', 'destination', path, '--as-fd', '1'],
                        stdout=subprocess.PIPE, check=True, timeout=30)
assert result.stdout == b'local producer'
# A preview or skip must finish even with an open, quiet input pipe.
import json, os, tempfile
with tempfile.TemporaryDirectory(prefix='syq-stream-results-') as directory:
    for index, options in enumerate((['--if-exists=keep', '--as', path],
                                    ['--only-existing', '--as', '/tmp/syq-real-ssh/preview-missing/object'],
                                    ['--dry-run', '--as', '/tmp/syq-real-ssh/preview-missing/object'])):
        read_fd, write_fd = os.pipe()
        try:
            results_path = directory + '/result-' + str(index)
            result = subprocess.run(['syq', 'cp', '--src-fd', '0', '--to', 'destination',
                                     *options, '--results', results_path], stdin=read_fd,
                                    capture_output=True, timeout=15)
            assert result.returncode == 0, result.stderr
            records = [json.loads(line) for line in open(results_path)]
            assert records[-1]['type'] == 'result' and records[-1]['exit_code'] == 0
            assert records[-1]['files_excluded'] == (index < 2)
            assert not result.stdout
        finally:
            os.close(read_fd)
            os.close(write_fd)
subprocess.run(['ssh', 'destination', 'test ! -e /tmp/syq-real-ssh/preview-missing'], check=True, timeout=15)
# A producer exception closes the control pipe without authorizing publication.
for commit in (b'', b'C'):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, commit)
    os.close(write_fd)
    try:
        result = subprocess.run(['syq', 'cp', '--src-fd', '0', '--to', 'destination',
                                 '--as', path, '--if-exists=update', '--stream-commit-fd', str(read_fd)],
                                input=payload, pass_fds=(read_fd,), timeout=60,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        os.close(read_fd)
    assert (result.returncode == 0) == (commit == b'C'), result.stderr
    result = subprocess.run(['syq', 'cp', '--from', 'destination', path, '--as-fd', '1'],
                            stdout=subprocess.PIPE, check=True, timeout=60)
    assert result.stdout == (payload if commit else b'local producer')
PY_DESCRIPTORS

printf 'case: remote mapping generation\n'
python3 /usr/local/libexec/syq-test-map-generation.py

printf 'case: shared stream mappings over TCP and SSH\n'
timeout --kill-after=5s 120s python3 /usr/local/libexec/syq-test-stream-mappings.py

printf 'case: pipelined prune lookup with a one-deep data pipeline\n'
python3 - <<'PY_PRUNE'
import pathlib
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix="syq-prune-") as directory:
    source = pathlib.Path(directory)
    for index in range(4096):
        (source / f"file-{index:04}").write_bytes(b"new content")
    destination = "/tmp/syq-real-ssh/prune-pipeline"
    subprocess.run(["ssh", "destination", f"mkdir -p {destination}; printf extra > {destination}/extra"], check=True, timeout=30)
    command = ["syq", "cp", "--srcs-in", str(source), "--to", "destination", "--into", destination,
               "--prune", "--no-tcp", "--no-progress", "--performance-tuning", "pipeline-depth=1"]
    subprocess.run(command + ["--dry-run"], check=True, timeout=90)
    subprocess.run(["ssh", "destination", f"test -f {destination}/extra && test ! -e {destination}/file-0000"], check=True, timeout=30)
    subprocess.run(command, check=True, timeout=120)
    subprocess.run(["ssh", "destination", f"test ! -e {destination}/extra && test $(find {destination} -type f | wc -l) -eq 4096 && test \"$(cat {destination}/file-4095)\" = 'new content'"], check=True, timeout=30)
PY_PRUNE

printf 'case: ordinary SSH directory push and pull across separate hosts\n'
mkdir -p /tmp/syq-ordinary-source/sub
printf 'ordinary cross-host directory copy\n' > /tmp/syq-ordinary-source/sub/file
syq rsync -a --no-progress --syq-no-tcp /tmp/syq-ordinary-source/ \
    destination:/tmp/syq-real-ssh/ordinary-push/
ssh destination 'cat /tmp/syq-real-ssh/ordinary-push/sub/file' | \
    cmp /tmp/syq-ordinary-source/sub/file -
syq rsync -a --no-progress --syq-no-tcp \
    destination:/tmp/syq-real-ssh/ordinary-push/ /tmp/syq-ordinary-pull/
cmp /tmp/syq-ordinary-source/sub/file /tmp/syq-ordinary-pull/sub/file

printf 'case: enrollment and restricted copies with OpenSSH 8.8\n'
python3 /usr/local/libexec/syq-test-receiver-old-openssh.py

printf 'case: enrollment and restricted copies on an RSA-only destination\n'
python3 /usr/local/libexec/syq-test-receiver-old-openssh.py --rsa-only

printf 'case: restricted SSH worker handshake, revocation, and resume\n'
python3 /usr/local/libexec/syq-test-receiver-revoke.py --no-tcp

printf 'case: long receiver home supports explicit SSH and blocked-TCP fallback\n'
ssh longhome@destination 'test "${#HOME}" -gt 36; mkdir -p /tmp/syq-long-home'
make_tree source /tmp/syq-real-ssh/long-home-source long-home
syq cp --no-progress --no-tcp --performance-tuning workers=2 --copy-metadata=permissions \
    --from source --srcs-in /tmp/syq-real-ssh/long-home-source \
    --to longhome@destination --into /tmp/syq-long-home/explicit
assert_same_tree source /tmp/syq-real-ssh/long-home-source \
    longhome@destination /tmp/syq-long-home/explicit long-home-explicit
syq cp --no-progress --performance-tuning workers=2 --copy-metadata=permissions \
    --tcp-ports "$blocked_tcp_port-$blocked_tcp_port" \
    --from source --srcs-in /tmp/syq-real-ssh/long-home-source \
    --to longhome@destination --into /tmp/syq-long-home/fallback
assert_same_tree source /tmp/syq-real-ssh/long-home-source \
    longhome@destination /tmp/syq-long-home/fallback long-home-fallback

printf 'case: ephemeral connect only reuses forward SSH and leaves receiving off\n'
ephemeral_connect_scope=$(syq persist on --ephemeral)
syq persist connect source --pscope "$ephemeral_connect_scope"
syq persist status --json --pscope "$ephemeral_connect_scope" > /tmp/syq-ephemeral-connected.json
python3 - <<'PYEPHEMERAL'
import json
from pathlib import Path
state = json.load(open("/tmp/syq-ephemeral-connected.json"))
connection = next(c for c in state["connections"] if c["endpoint"] == "source")
assert connection["state"] == "ready" and connection["ssh_connected"], connection
assert connection["receiving_enabled"] is False and connection["receiving"] is None, connection
# Endpoint records let a later receive-on start without another connect.
# Receiving is disabled: no profile is running and no listener exists.
assert connection["receiving_profiles"] == [], connection
entries = [p.name for p in Path(state["scope"]).iterdir()]
assert not any(name.endswith(".recv") for name in entries), entries
PYEPHEMERAL
syq persist status --json | python3 -c 'import json,sys; assert json.load(sys.stdin)["enabled"] is False'
syq persist off --pscope "$ephemeral_connect_scope"

printf 'case: connecting again replaces a scoped receiving connection from another build\n'
# After an upgrade on macOS, a receiving connection from the old build gives
# `syq persist connect SERVER --pscope PATH` as its restart. Running that
# stops the old connection, starts one from this build, and keeps the domain
# and its settings.
upgrade_scope=$(syq persist on --ephemeral)
mkdir -p /tmp/syq-upgrade-receive
syq persist receive on --pscope "$upgrade_scope" --notify off \
    --root /tmp/syq-upgrade-receive --all-connections
syq persist connect source --pscope "$upgrade_scope"
cp "$upgrade_scope/receive.json" /tmp/syq-upgrade-settings.json
rm -f /tmp/syq-upgrade-old-ready
# Stand in for the old build: stop this build's connection, then answer on its
# control with another build's identity until asked to stop.
python3 - "$upgrade_scope" /tmp/syq-upgrade-old-ready "$(syq --build-identity)" \
    >/tmp/syq-upgrade-old.log 2>&1 <<'PYOLD' &
import fcntl, json, os, signal, socket, struct, sys, time
from pathlib import Path

scope, ready, build = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
records = [p for p in scope.iterdir() if p.name.endswith(".recv-json")]
assert len(records) == 1, records
control = str(records[0])[: -len(".recv-json")]


def read_frame(conn):
    data = b""
    while len(data) < 4 or len(data) < 4 + struct.unpack(">I", data[:4])[0]:
        chunk = conn.recv(65536)
        if not chunk:
            raise EOFError("short frame")
        data += chunk
    return json.loads(data[4:])


def write_frame(conn, message):
    data = json.dumps(message).encode()
    conn.sendall(struct.pack(">I", len(data)) + data)


with socket.socket(socket.AF_UNIX) as conn:
    conn.settimeout(5)
    conn.connect(control + ".recv")
    write_frame(conn, {"version": 2, "stop": False})
    state = read_frame(conn)
assert state["identity"] == build, state
os.kill(state["pid"], signal.SIGTERM)
lock = open(control + ".recv-lock", "r+")
deadline = time.monotonic() + 15
while True:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not os.path.exists(control + ".recv"):
            break
        fcntl.flock(lock, fcntl.LOCK_UN)
    except BlockingIOError:
        pass
    assert time.monotonic() < deadline, "this build's receiving connection did not stop"
    time.sleep(0.02)
listener = socket.socket(socket.AF_UNIX)
listener.bind(control + ".recv")
os.chmod(control + ".recv", 0o600)
listener.listen(8)
listener.settimeout(60)
ready.touch()
while True:
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(5)
        stop = read_frame(conn).get("stop")
        write_frame(conn, {
            "version": 2, "identity": "other-build", "pid": 0,
            "endpoint": "source", "name": "",
            "connection": {"phase": "online", "error": None, "ssh_pid": None},
        })
    if stop:
        # Like the service, remove the socket before releasing the lock.
        os.unlink(control + ".recv")
        lock.close()
        print("stopped")
        break
PYOLD
upgrade_old_pid=$!
upgrade_deadline=$(($(date +%s) + 30))
while [ ! -e /tmp/syq-upgrade-old-ready ]; do
    if ! kill -0 "$upgrade_old_pid" 2>/dev/null || [ "$(date +%s)" -ge "$upgrade_deadline" ]; then
        cat /tmp/syq-upgrade-old.log >&2
        exit 1
    fi
    sleep 0.1
done
# The restart the old build's message gives.
syq persist connect source --pscope "$upgrade_scope"
wait "$upgrade_old_pid"
upgrade_old_pid=
test "$(cat /tmp/syq-upgrade-old.log)" = stopped
cmp "$upgrade_scope/receive.json" /tmp/syq-upgrade-settings.json
syq persist status --json --pscope "$upgrade_scope" | python3 -c '
import json, sys
state = json.load(sys.stdin)
connection = next(c for c in state["connections"] if c["endpoint"] == "source")
assert connection["state"] == "ready", connection
assert connection["receiving"]["phase"] == "online", connection
'
syq persist off --pscope "$upgrade_scope"
upgrade_scope=

printf 'case: a receiving service switches to a new build installed where it was started from\n'
# Receive with another build installed at /tmp/syq-switch-bin/syq, then
# update that file to this build, as an installer would. The service notices
# and, once idle, runs the new build's connect, which installs its helper on
# the server and replaces the service. Nothing else is run.
switch_scope=$(syq persist on --ephemeral)
mkdir -p /tmp/syq-switch-bin /tmp/syq-switch-receive
chmod 0755 /tmp/syq-switch-bin
cp /usr/local/bin/syq-other-build /tmp/syq-switch-bin/syq
SYQ_TEST_SWITCH_CHECK_MS=200 SYQ_TEST_SWITCH_QUIET_MS=1000 \
    /tmp/syq-switch-bin/syq persist receive on --pscope "$switch_scope" --notify off \
    --root /tmp/syq-switch-receive --all-connections
SYQ_TEST_SWITCH_CHECK_MS=200 SYQ_TEST_SWITCH_QUIET_MS=1000 \
    /tmp/syq-switch-bin/syq persist connect source --pscope "$switch_scope"
cp "$switch_scope/receive.json" /tmp/syq-switch-settings.json
other_build=$(syq-other-build --build-identity)
this_build=$(syq --build-identity)
syq persist receive status --json --pscope "$switch_scope" | python3 -c '
import json, sys
state = json.load(sys.stdin)
(connection,) = state["connections"]
assert connection["identity"] == sys.argv[1], connection
assert connection["started_from"] == "/tmp/syq-switch-bin/syq", connection
assert connection["connection"]["phase"] == "online", connection
' "$other_build"
cp /usr/local/bin/syq /tmp/syq-switch-bin/syq.new
mv /tmp/syq-switch-bin/syq.new /tmp/syq-switch-bin/syq
python3 - "$switch_scope" "$this_build" <<'PYSWITCH'
import json, subprocess, sys, time

scope, build = sys.argv[1], sys.argv[2]
deadline = time.monotonic() + 90
progress = time.monotonic()
while True:
    state = json.loads(subprocess.run(
        ["syq", "persist", "receive", "status", "--json", "--pscope", scope],
        check=True, capture_output=True, text=True).stdout)
    connections = state["connections"]
    if (len(connections) == 1 and connections[0]["identity"] == build
            and connections[0]["connection"]["phase"] == "online"):
        assert connections[0]["started_from"] == "/tmp/syq-switch-bin/syq", connections
        break
    if time.monotonic() >= deadline:
        raise SystemExit(f"receiving did not switch to {build}: {connections}")
    if time.monotonic() >= progress:
        print(f"waiting for receiving to switch: {connections}", file=sys.stderr)
        progress = time.monotonic() + 10
    time.sleep(0.5)
PYSWITCH
cmp "$switch_scope/receive.json" /tmp/syq-switch-settings.json
syq persist off --pscope "$switch_scope"
switch_scope=

printf 'case: named return destination works from independent server shells without agent forwarding\n'
receive_root=/tmp/syq-real-ssh-receive
mkdir -p "$receive_root" /tmp/syq-real-ssh-receive-other
make_tree source /tmp/syq-real-ssh/return-source return
# A failed receiving setup is an error from connect, and another connect repairs
# that one service after the cause is fixed, without toggling receive settings.
ssh source 'cat > /tmp/syq-connect-helper && chmod +x /tmp/syq-connect-helper && touch /tmp/syq-connect-fail' <<'HELPER'
#!/bin/sh
if [ "$1" = --destination-register ] && [ -e /tmp/syq-connect-fail ]; then
    echo 'intentional registration failure for connect recovery' >&2
    exit 1
fi
exec /usr/local/bin/syq "$@"
HELPER
if syq persist connect source --syq-path /tmp/syq-connect-helper --timeout 10; then
    echo 'connect reported ready after receiving failed' >&2
    exit 1
fi
syq persist status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); c=next(c for c in s["connections"] if c["endpoint"] == "source"); assert c["state"]=="failed" and "intentional registration failure" in c["receiving"]["error"],c'
ssh source 'rm /tmp/syq-connect-fail'
syq persist connect source --syq-path /tmp/syq-connect-helper --timeout 10
syq persist off
ssh source 'rm /tmp/syq-connect-helper'
# Connecting prepares both directions without a dummy copy or receive wait.
syq persist connect source
syq persist status --json > /tmp/syq-connected.json
python3 - <<'PYCONNECT'
import json
state = json.load(open("/tmp/syq-connected.json"))
assert state["enabled"] is True, state
connection = next(c for c in state["connections"] if c["endpoint"] == "source")
assert connection["state"] == "ready" and connection["ssh_connected"], connection
assert connection["receiving"]["phase"] == "online", connection
PYCONNECT
test ! -e /tmp/syq-return-pull
syq cp --from source --srcs-in /tmp/syq-real-ssh/return-source --into /tmp/syq-return-pull
# The container hostname is the laptop's default advertised name.
# shellcheck disable=SC2029
ssh source "syq persist destinations wait $(hostname) --timeout 5"
syq persist receive on --name laptop --root "$receive_root"
syq persist receive remove "$(hostname)"
syq persist receive wait source --timeout 30
ssh source 'syq persist destinations wait laptop --timeout 30'
# The return connection's secret reaches the server on standard input, never
# in a command line that other users there can read.
ssh source python3 - <<'PY_RETURN_SECRET'
import json
import os
from pathlib import Path

record = Path.home() / ".syq-destinations-v3" / "laptop.json"
secret = json.loads(record.read_text())["secret"].encode()
registering = 0
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        arguments = (Path("/proc") / entry / "cmdline").read_bytes()
    except OSError:
        continue
    assert secret not in arguments, arguments
    registering += b"--destination-register\0" in arguments
assert registering, "no registration process was found"
PY_RETURN_SECRET
printf 'case: hardlinks survive SSH and TCP copies, updates, reruns, and pulls\n'
python3 - <<'PY_HARDLINKS'
import os
from pathlib import Path
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix='syq-hardlinks-') as scratch:
    source = Path(scratch) / 'source'
    source.mkdir()
    (source / 'a').write_bytes(b'first')
    os.link(source / 'a', source / 'b')
    for label, transport in [('ssh', ['--no-tcp']), ('tcp', [])]:
        destination = '/tmp/syq-real-ssh/hardlinks-' + label
        command = ['syq', 'cp', '--copy-metadata=hardlinks', '--srcs-in', str(source), '--to', 'destination', '--into', destination, *transport]
        subprocess.run(command, check=True, timeout=30)
        subprocess.run(command, check=True, timeout=30)
        (source / 'a').write_bytes(b'changed payload')
        subprocess.run([*command, '--if-exists=update', '--in-place=new'], check=True, timeout=30)
        pull = Path(scratch) / label
        subprocess.run(['syq', 'cp', '--copy-metadata=hardlinks', '--from', 'destination', '--srcs-in', destination, '--into', str(pull), *transport], check=True, timeout=30)
        assert (pull / 'a').read_bytes() == b'changed payload'
        assert (pull / 'b').read_bytes() == b'changed payload'
        assert (pull / 'a').stat().st_ino == (pull / 'b').stat().st_ino
PY_HARDLINKS

python3 /usr/local/libexec/syq-test-metadata.py

printf 'case: return copies await local approval and denial leaves no destination\n'
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as denied' &
return_copy_pid=$!
syq persist receive pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; r=json.load(open("/tmp/syq-pending.json")); assert len(r)==1 and "source" in r[0]["from"] and "denied" in r[0]["destination"],r; print(r[0]["id"])')
test ! -e "$receive_root/denied"
# A repeated connect must preserve the daemon and the pending approval.
python3 - <<'PYCONNECT'
import json, subprocess
before = json.loads(subprocess.check_output(["syq", "persist", "receive", "status", "--json"]))["connections"]
subprocess.run(["syq", "persist", "connect", "source"], check=True, timeout=15)
after = json.loads(subprocess.check_output(["syq", "persist", "receive", "status", "--json"]))["connections"]
before = next(c for c in before if c["endpoint"] == "source")
after = next(c for c in after if c["endpoint"] == "source")
assert before["pid"] == after["pid"], (before, after)
assert before["connection"]["ssh_pid"] == after["connection"]["ssh_pid"], (before, after)
assert [p["id"] for p in before["pending"]] == [p["id"] for p in after["pending"]] != [], (before, after)
PYCONNECT
syq persist receive deny "$request_id"
if wait "$return_copy_pid"; then echo 'denied copy succeeded' >&2; exit 1; else test "$?" -ne 124; fi
return_copy_pid=
test ! -e "$receive_root/denied"
if syq persist receive approve "$request_id"; then echo 'denied approval ID was reused' >&2; exit 1; fi

printf 'case: approval allows the pending 128-worker copy once\n'
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as approved --performance-tuning workers=128' &
return_copy_pid=$!
syq persist receive pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
test ! -e "$receive_root/approved"
syq persist receive approve "$request_id"
wait "$return_copy_pid"
return_copy_pid=
printf 'return\n' | cmp - "$receive_root/approved"
if syq persist receive approve "$request_id"; then echo 'used approval ID was reused' >&2; exit 1; fi

printf 'case: the server paces a capped copy to the laptop on the bytes it sends\n'
ssh source python3 - <<'PY_PACED_SOURCE'
import os
from pathlib import Path

source = Path("/tmp/syq-real-ssh/paced-return")
source.mkdir(parents=True, exist_ok=True)
# 8 MiB that compresses to a few kilobytes, and 1 MiB that does not.
(source / "compressible").write_bytes(b"syq pacing test\n" * (1 << 19))
(source / "random").write_bytes(os.urandom(1 << 20))
PY_PACED_SOURCE
python3 - <<'PY_PACED_RETURN'
import hashlib
import json
import shlex
import subprocess


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout


# The TCP copy fails rather than falling back to SSH data.
for label, environment, transport in [("tcp", ["env", "SYQ_TEST_REQUIRE_TCP=1"], []),
                                      ("ssh", [], ["--no-tcp"])]:
    results = f"/tmp/syq-real-ssh/paced-return-{label}.ndjson"
    command = [*environment, "syq", "cp", "--srcs-in", "/tmp/syq-real-ssh/paced-return",
               "--to", "@laptop", "--into", f"paced-{label}",
               "--resource-limits", "bandwidth=2M", f"--results={results}", *transport]
    copy = subprocess.Popen(["ssh", "source", shlex.join(command)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        pending = json.loads(run("syq", "persist", "receive", "pending", "--wait",
                                 "--timeout", "10", "--json"))
        assert len(pending) == 1, pending
        run("syq", "persist", "receive", "approve", pending[0]["id"])
        output, _ = copy.communicate(timeout=60)
    finally:
        if copy.poll() is None:
            copy.kill()
            copy.wait(timeout=5)
    assert copy.returncode == 0, output
    terminal = json.loads(run("ssh", "source", "tail -n 1 " + shlex.quote(results)))
    # The megabyte that does not compress takes half a second at 2 MiB/s.
    # Pacing file data rather than the bytes sent would take four seconds
    # more for the rest.
    transfer_ms = terminal["timings"]["transfer_ms"]
    assert 400 <= transfer_ms < 3000, (label, terminal)
    expected = run("ssh", "source", "sha256sum /tmp/syq-real-ssh/paced-return/random").split()[0]
    with open(f"/tmp/syq-real-ssh-receive/paced-{label}/random", "rb") as copied:
        assert hashlib.sha256(copied.read()).hexdigest() == expected, label
    print(json.dumps({"route": "to the laptop", "transport": label,
                      "transfer_ms": transfer_ms}), flush=True)
PY_PACED_RETURN

printf 'case: disconnected requests cannot be approved later\n'
ssh source 'timeout 2 syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as disconnected' &
return_copy_pid=$!
syq persist receive pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
if wait "$return_copy_pid"; then echo 'unapproved copy succeeded' >&2; exit 1; fi
return_copy_pid=
python3 - <<'PYWAIT'
import json, subprocess, time
deadline = time.monotonic() + 3
while True:
    pending = json.loads(subprocess.check_output(["syq", "persist", "receive", "pending", "--json"]))
    if not pending: break
    assert time.monotonic() < deadline, pending
    time.sleep(.05)
PYWAIT
if syq persist receive approve "$request_id"; then echo 'disconnected request was approved' >&2; exit 1; fi
test ! -e "$receive_root/disconnected"

printf 'case: changing policy cancels a pending request\n'
max_entries=$(syq persist receive status --json | python3 -c 'import json,sys; value=json.load(sys.stdin)["settings"]["max_entries"]; assert value > 1; print(value)')
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as cancelled-policy' &
return_copy_pid=$!
syq persist receive pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
# Notification delivery is harmless; change an actual access limit instead.
syq persist receive on --max-entries "$((max_entries - 1))" --notify off
if wait "$return_copy_pid"; then echo 'cancelled copy succeeded' >&2; exit 1; else test "$?" -ne 124; fi
return_copy_pid=
syq persist receive wait source --timeout 30
if syq persist receive approve "$request_id"; then echo 'cancelled request was approved' >&2; exit 1; fi
test ! -e "$receive_root/cancelled-policy"
syq persist receive on --max-entries "$max_entries"
syq persist receive wait source --timeout 30

printf 'case: native Linux notification actions control return copies\n'
dbus-run-session -- python3 /usr/local/libexec/syq-test-receive-notifications.py

printf 'case: return copies hand off between server PATH builds\n'
python3 /usr/local/libexec/syq-test-return-handoff.py
ssh source 'python3 /usr/local/libexec/syq-test-handoff-timing.py syq-other-build syq'

printf 'case: forward copies authorized through the return connection\n'
python3 /usr/local/libexec/syq-test-forward-copy.py

printf 'case: remote commands run through the return connection\n'
python3 /usr/local/libexec/syq-test-return-exec.py

printf 'case: downloads from another server read through its enrolled receiver\n'
python3 /usr/local/libexec/syq-test-pull-copy.py

printf 'case: servers copy files from the laptop it approves\n'
python3 /usr/local/libexec/syq-test-send-copy.py

printf 'case: direct SSH sessions authorized through the return connection\n'
python3 /usr/local/libexec/syq-test-return-ssh.py

printf 'case: native tools reuse laptop-approved account connections\n'
python3 /usr/local/libexec/syq-test-ssh-tools.py

printf 'case: ordinary SSH provider account access without agent forwarding\n'
python3 /usr/local/libexec/syq-test-provider-ssh.py

printf 'case: receiving switches to a new build once an approved account connection is idle\n'
python3 /usr/local/libexec/syq-test-account-switch.py

printf 'case: copies between two other servers run on the enrolled source\n'
python3 /usr/local/libexec/syq-test-between-servers.py

printf 'case: storage authorization through the return connection\n'
python3 /usr/local/libexec/syq-test-storage-authorization.py

printf 'case: explicit automatic approval supports unattended copies\n'
syq persist receive on --auto-approve-root "$receive_root"
syq persist receive wait source --timeout 30
ssh source 'test -z "${SSH_AUTH_SOCK:-}"; SYQ_TEST_REQUIRE_TCP=1 syq cp --performance-tuning workers=2 --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/return-source --to @laptop --into first'
remote_manifest source /tmp/syq-real-ssh/return-source /tmp/syq-return-source.manifest
(
    cd "$receive_root/first"
    {
        find . -mindepth 1 -printf '%y %m %p -> %l\n'
        find . -type f -exec sha256sum {} +
    } | LC_ALL=C sort
) > /tmp/syq-return-local.manifest
diff -u /tmp/syq-return-source.manifest /tmp/syq-return-local.manifest
ssh_copy_summary=$(ssh source 'syq cp --no-tcp /tmp/syq-real-ssh/return-source/subdir/chunks.bin --to @laptop --as ssh-copy')
cmp "$receive_root/first/subdir/chunks.bin" "$receive_root/ssh-copy"
# The server's summary says where on the laptop the files went: the profile's
# directory, which the server's command does not name.
case "$ssh_copy_summary" in
    *" to @laptop:$receive_root/ssh-copy, "*) ;;
    *)
        printf 'the summary does not say where the copy went on the laptop:\n%s\n' "$ssh_copy_summary" >&2
        exit 1
        ;;
esac
ssh source 'syq cp --dry-run --hash --srcs-in /tmp/syq-real-ssh/return-source --to @laptop --into first --results-fd 3 3>&1 1>/dev/null' > /tmp/syq-return-preview.ndjson
assert_preview_counts /tmp/syq-return-preview.ndjson 0 3
ssh source 'syq cp --if-exists=keep /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as first/message.txt'

ssh source 'python3 /usr/local/libexec/syq-test-restricted-mapping.py named'

printf 'case: named return rejects traversal and receiver symlink escape\n'
ln -s /tmp/syq-real-ssh-receive-other "$receive_root/escape"
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as escape/escaped'; then
    echo 'named destination followed an escaping destination symlink' >&2
    exit 1
fi
test ! -e /tmp/syq-real-ssh-receive-other/escaped
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as ../escaped'; then
    echo 'named destination accepted parent traversal' >&2
    exit 1
fi

printf 'case: a copied receiver identity cannot displace a responsive laptop\n'
(
    original_receiver_identity=$HOME/.syq-receiver-identity
    export HOME=/tmp/syq-duplicate-home XDG_RUNTIME_DIR=/tmp/syq-duplicate-runtime XDG_CONFIG_HOME=/tmp/syq-duplicate-config
    mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
    cp -a "$original_receiver_identity" "$HOME/"
    trap 'syq persist off' EXIT
    syq persist on
    syq persist receive on --name laptop --root /tmp/syq-real-ssh-receive-other
    syq cp --from source --srcs-in /tmp/syq-real-ssh/return-source --into /tmp/syq-duplicate-pull
    if syq persist receive wait source --timeout 5; then
        echo 'duplicate named destination unexpectedly succeeded' >&2
        exit 1
    fi
    syq persist receive status --json | python3 -c 'import json,sys; states=json.load(sys.stdin)["connections"]; assert any(s["connection"]["phase"] == "failed" and "already connected" in s["connection"]["error"] for s in states), states'
)
ssh source 'syq persist destinations wait laptop --timeout 5'

printf 'case: interrupted named copy fails, laptop reconnects, and retry resumes\n'
ssh source 'dd if=/dev/urandom of=/tmp/syq-real-ssh/return-source/resume.bin bs=1M count=16 status=none'
source_prefix=$(ssh source 'dd if=/tmp/syq-real-ssh/return-source/resume.bin bs=1M count=4 status=none | sha256sum')
# One worker writes the file from its start, so its first 4 MiB arrive
# after 8 seconds at this rate; several would each fill a part of it.
timeout 45 ssh source 'SYQ_TEST_REQUIRE_TCP=1 syq cp --resource-limits bandwidth=512,workers=1 /tmp/syq-real-ssh/return-source/resume.bin --to @laptop --as interrupted' &
return_copy_pid=$!
deadline=$(($(date +%s) + 25))
next_progress=$(($(date +%s) + 5))
while :; do
    partial_count=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-tmp.*' | wc -l)
    if [ "$partial_count" -eq 1 ]; then
        partial=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-tmp.*')
        partial_prefix=$(dd if="$partial" bs=1M count=4 status=none | sha256sum)
        if [ "$partial_prefix" = "$source_prefix" ]; then break; fi
    fi
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
        echo "named partial readiness timed out: partial_count=$partial_count" >&2
        exit 1
    fi
    if [ "$now" -ge "$next_progress" ]; then
        echo "waiting for named copy partial: partial_count=$partial_count" >&2
        next_progress=$((now + 5))
    fi
    sleep 0.1
done
# One complete 4 MiB prefix is now present and eligible for resume checks.
# Only kill the receiver's owned SSH child; the tracing wrapper is its parent.
receive_wrapper=$(syq persist receive status --json | python3 -c 'import json,sys; print(next(s["connection"]["ssh_pid"] for s in json.load(sys.stdin)["connections"] if s["endpoint"] == "source"))')
pkill -KILL -P "$receive_wrapper" -x ssh
if wait "$return_copy_pid"; then
    echo 'interrupted named transfer reported success' >&2
    exit 1
else
    interrupted_status=$?
    test "$interrupted_status" -ne 124
fi
return_copy_pid=
test ! -e "$receive_root/interrupted"
ssh source 'syq persist destinations wait laptop --timeout 30'
ssh source 'SYQ_TEST_REQUIRE_TCP=1 syq cp /tmp/syq-real-ssh/return-source/resume.bin --to @laptop --as interrupted'
ssh source 'cat /tmp/syq-real-ssh/return-source/resume.bin' | cmp - "$receive_root/interrupted"
test "$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-tmp.*' | wc -l)" -eq 1
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-reconnect'
printf 'return\n' | cmp - "$receive_root/after-reconnect"
printf 'case: return heartbeat timeout reconnects without toggling persistence\n'
python3 - <<'PYTEST'
import json
import os
import signal
import subprocess
import time

state = json.loads(subprocess.check_output(["syq", "persist", "receive", "status", "--json"]))
wrapper = next(s["connection"]["ssh_pid"] for s in state["connections"] if s["endpoint"] == "source")
transport = int(subprocess.check_output(["pgrep", "-P", str(wrapper), "-x", "ssh"]))
# Pause the real client so the server can open its forwarded socket but cannot
# receive a heartbeat reply. This produces a server-side socket timeout, unlike
# killing SSH, which usually gives the client a transport exit status of 255.
os.kill(transport, signal.SIGSTOP)
try:
    deadline = time.monotonic() + 40
    while True:
        result = subprocess.run(["ssh", "source", "test ! -e ~/.syq-destinations-v3/laptop.json"], timeout=5)
        if result.returncode == 0:
            break
        assert result.returncode == 1, result.returncode
        assert time.monotonic() < deadline, "heartbeat deadline: old registration still advertised"
        print("waiting for the paused return connection's heartbeat to time out", flush=True)
        time.sleep(2)
finally:
    os.kill(transport, signal.SIGCONT)
subprocess.run(["ssh", "source", "syq persist destinations wait laptop --timeout 40"], check=True, timeout=45)
subprocess.run(["syq", "persist", "receive", "wait", "source", "--timeout", "10"], check=True, timeout=15)
with open("/tmp/syq-real-ssh-ssh.trace") as trace:
    ends = [dict(field.split("=", 1) for field in line.strip().split("\t")) for line in trace if line.startswith("phase=end\t")]
assert any(row["pid"] == str(wrapper) and row["status"] == "75" for row in ends), "heartbeat did not report retry status 75"
print("return connection recovered after the server heartbeat timed out", flush=True)
PYTEST
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-heartbeat-timeout'
printf 'return\n' | cmp - "$receive_root/after-heartbeat-timeout"
printf 'case: cwd permits destinations outside its starting directory\n'
syq persist receive on --cwd "$receive_root" --no-root --auto-approve-root /tmp
syq persist receive wait source --timeout 30
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as ../syq-return-outside'
printf 'return\n' | cmp - /tmp/syq-return-outside
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as /tmp/syq-return-absolute'
printf 'return\n' | cmp - /tmp/syq-return-absolute
python3 /usr/local/libexec/syq-test-receive-profiles.py
printf 'case: persist receive off/on keeps ordinary persistence and restarts receiving\n'
syq persist receive off
syq persist connect source
syq persist status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); c=next(c for c in s["connections"] if c["endpoint"] == "source"); assert c["state"]=="ready" and c["receiving_enabled"] is False and c["receiving"] is None,c'
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as while-disabled'; then
    echo 'disabled receiving unexpectedly accepted a transfer' >&2
    exit 1
fi
syq persist receive on
syq persist receive wait source --timeout 30
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as reenabled'
printf 'return\n' | cmp - "$receive_root/reenabled"
printf 'case: persistence off stops background receiving\n'
syq persist off
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-stop'; then
    echo 'stopped receiver unexpectedly accepted a transfer' >&2
    exit 1
fi
test ! -e "$receive_root/after-stop"
ssh source 'test ! -e ~/.syq-destinations-v3/laptop.json'
printf 'case: offline names require the original receiver identity or explicit replacement\n'
python3 /usr/local/libexec/syq-test-receiver-identity.py
# Unrelated pooling scenarios count SSH commands; explicitly disable receiving.
syq persist receive off
syq completion cache clear >/dev/null

printf 'case: shell completion adapters parse and keep descriptions separate\n'
# Each PTY check owns its home, cache, fixture tree, and shell process group.
completion_pids=
for completion_shell in bash zsh fish; do
    python3 /usr/local/libexec/syq-test-completion-display.py --syq /usr/local/bin/syq --shell "$completion_shell" &
    completion_pids="$completion_pids $!"
done
completion_status=0
for completion_pid in $completion_pids; do
    wait "$completion_pid" || completion_status=1
done
[ "$completion_status" -eq 0 ] || exit 1
syq completion bash > /tmp/syq-completion.bash
bash -n /tmp/syq-completion.bash
syq completion zsh > /tmp/syq-completion.zsh
zsh -n /tmp/syq-completion.zsh
syq completion fish > /tmp/syq-completion.fish
fish -n /tmp/syq-completion.fish
mkdir -p /tmp/syq-real-ssh/completion-adapters
printf 'hello' > /tmp/syq-real-ssh/completion-adapters/alpha
fish -c 'source /tmp/syq-completion.fish; complete -C "syq cp /tmp/syq-real-ssh/completion-adapters/al"' > /tmp/syq-fish-details
awk -F '\t' '$1 == "/tmp/syq-real-ssh/completion-adapters/alpha" && $2 ~ /^-rw/ && $2 ~ /5 B/ && $2 ~ /UTC/ { found=1 } END { exit !found }' /tmp/syq-fish-details

printf 'case: remote filename completion reuses a persistent ordinary SSH login\n'
ssh source 'rm -rf /tmp/syq-real-ssh/completion; mkdir -p /tmp/syq-real-ssh/completion/alpine; : > "/tmp/syq-real-ssh/completion/alpha file"'
# Observe the environment at the remote helper, after real SendEnv/AcceptEnv
# processing. The helper still executes the candidate syq binary unchanged.
ssh source 'cat > /tmp/syq-real-ssh/completion-helper; chmod 0700 /tmp/syq-real-ssh/completion-helper' <<'EOF'
#!/bin/sh
printf '%s\n' "${SYQ_REAL_SSH_SENT_ENV-unset}" >> /tmp/syq-real-ssh/completion-env.log
exec /usr/local/bin/syq "$@"
EOF
export SYQ_REAL_SSH_SENT_ENV=pool-original
trace=/tmp/syq-real-ssh-ssh.trace
rm -f "$trace"
syq persist on >/dev/null
completion_output=/tmp/syq-real-ssh-completion.out
completion_expected=/tmp/syq-real-ssh-completion.expected
{
    printf '%s\000' '/tmp/syq-real-ssh/completion/alpha file'
    printf '%s\000' '/tmp/syq-real-ssh/completion/alpine/'
} >"$completion_expected"
complete_remote() {
    syq completion __complete fish 6 -- \
        syq cp --syq-path /tmp/syq-real-ssh/completion-helper --from source \
        /tmp/syq-real-ssh/completion/al >"$completion_output"
    cmp "$completion_expected" "$completion_output"
}
# Completed logins of the completion's own: the first becomes the master.
direct_logins() {
    awk -F '\t' '
        $1 == "phase=end" &&
        $3 == "host=source" &&
        $4 == "control_master=auto" &&
        $8 == "status=0" { count++ }
        END { print count + 0 }
    ' "$trace"
}
# Sessions the pool holds open through the master: attached with
# ControlMaster=no to a present socket and not yet ended. A master check
# starts and ends at once, so it never counts here.
open_spares() {
    awk -F '\t' '
        $3 == "host=source" &&
        $4 == "control_master=no" &&
        $6 == "control_socket=present" {
            if ($1 == "phase=start") open++
            if ($1 == "phase=end") open--
        }
        END { print open + 0 }
    ' "$trace"
}
complete_remote
# Completion can return just before its tracing SSH wrapper logs process exit.
# Wait for that structured event before asserting the completed login count.
deadline=$(($(date +%s) + 5))
while :; do
    logins=$(direct_logins)
    if [ "$logins" -eq 1 ]; then break; fi
    if [ "$logins" -gt 1 ] || [ "$(date +%s)" -ge "$deadline" ]; then
        echo "first completion login count: expected 1, observed $logins" >&2
        cat "$trace" >&2
        exit 1
    fi
    sleep 0.1
done
deadline=$(($(date +%s) + 15))
next_progress=$(($(date +%s) + 5))
while :; do
    spares=$(open_spares)
    if [ "$spares" -ge 1 ]; then
        break
    fi
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
        echo "session pool readiness timed out: open_spares=$spares" >&2
        cat "$trace" >&2
        exit 1
    fi
    if [ "$now" -ge "$next_progress" ]; then
        echo "waiting for session pool: open_spares=$spares" >&2
        next_progress=$((now + 5))
    fi
    sleep 0.1
done
syq persist status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); assert any(c["session_pool"] for c in s["connections"]),s'
# Later completions take the ready session: no login of their own, and
# their changed environment does not replace the pool's inherited values.
export SYQ_REAL_SSH_SENT_ENV=caller-changed
complete_remote
complete_remote
if [ "$(direct_logins)" -ne 1 ]; then
    echo 'a later completion opened its own SSH login instead of taking the pooled session:' >&2
    cat "$trace" >&2
    exit 1
fi
test "$(syq completion cache list)" = source
syq completion cache clear >/dev/null
syq persist off >/dev/null

ssh source 'cat /tmp/syq-real-ssh/completion-env.log' > /tmp/syq-real-ssh-completion-env.out
awk '
    $0 != "pool-original" { bad = 1 }
    END { exit (bad || NR < 2) }
' /tmp/syq-real-ssh-completion-env.out || {
    echo 'pooled helper did not keep the spawning environment:' >&2
    cat /tmp/syq-real-ssh-completion-env.out >&2
    exit 1
}
printf 'case: direct SSH helper sees the current SendEnv value\n'
complete_remote
test "$(ssh source 'tail -n 1 /tmp/syq-real-ssh/completion-env.log')" = caller-changed
printf 'case: restarting persistence adopts the new environment\n'
ssh source ': > /tmp/syq-real-ssh/completion-env.log'
syq persist on >/dev/null
complete_remote
syq persist off >/dev/null
ssh source 'cat /tmp/syq-real-ssh/completion-env.log' > /tmp/syq-real-ssh-completion-env.out
awk '
    $0 != "caller-changed" { bad = 1 }
    END { exit (bad || NR < 1) }
' /tmp/syq-real-ssh-completion-env.out
unset SYQ_REAL_SSH_SENT_ENV
syq completion cache clear >/dev/null

printf 'case: remote completion details use remote metadata without persistence\n'
SYQ_COMPLETION_DETAILS=1 syq completion __complete fish 4 -- syq cp --from source /tmp/syq-real-ssh/completion/al > /tmp/syq-completion-details
tr '\000' '\n' < /tmp/syq-completion-details > /tmp/syq-completion-details-lines
awk -F '\t' '
    $1 == "/tmp/syq-real-ssh/completion/alpha file" && $2 ~ /^-rw/ && $2 ~ /syq +syq/ && $2 ~ /0 B/ && $2 ~ /UTC/ { file=1 }
    $1 == "/tmp/syq-real-ssh/completion/alpine/" && $2 ~ /^d/ && $2 ~ /UTC/ { directory=1 }
    END { exit !(file && directory) }
' /tmp/syq-completion-details-lines


printf 'case: small native push to an ordinary SSH destination takes one turn\n'
small_source=/tmp/syq-real-ssh-small.bin
small_debug=/tmp/syq-real-ssh-small.debug
small_results=/tmp/syq-real-ssh-small.ndjson
head -c 1024 /dev/urandom >"$small_source"
ssh source 'rm -rf /tmp/syq-real-ssh/small-destination && install -d /tmp/syq-real-ssh/small-destination'
SYQ_DEBUG=1 syq cp --no-progress --results "$small_results" \
    "$small_source" --to source --into /tmp/syq-real-ssh/small-destination \
    2>"$small_debug"
small_status=$(tail -n 1 "$small_results")
case "$small_status" in
    *'"status":"success"'*'"type":"result"'*) ;;
    *)
        echo 'small push did not settle successfully:' >&2
        cat "$small_results" "$small_debug" >&2
        exit 1
        ;;
esac
if ! grep -q 'small copy: published' "$small_debug"; then
    echo 'small push did not use the one-turn path:' >&2
    cat "$small_debug" >&2
    exit 1
fi
small_expected=$(sha256sum "$small_source" | cut -d ' ' -f 1)
small_actual=$(ssh source 'sha256sum /tmp/syq-real-ssh/small-destination/syq-real-ssh-small.bin' | cut -d ' ' -f 1)
test "$small_expected" = "$small_actual"

printf 'case: persistent debug output closes with the copying process\n'
small_scope=$(syq persist on --ephemeral)
# A verbose detached SSH master holds this pipe open until ControlPersist
# expires. Do not close the scope until the pipeline has drained (or timed out).
small_exit=/tmp/syq-real-ssh-persistent-debug.exit
# Arguments and exit status are expanded by the timed child shell.
# shellcheck disable=SC2016
if timeout 15 sh -c '
    { SYQ_DEBUG=1 syq cp --no-progress --pscope "$1" "$2" \
        --to source --into /tmp/syq-real-ssh/small-destination
      echo "$?" >"$3"
    } 2>&1 | cat
' sh "$small_scope" "$small_source" "$small_exit" >"$small_debug"; then
    small_timeout=0
else
    small_timeout=$?
fi
syq persist off --pscope "$small_scope" >/dev/null
if [ "$small_timeout" -ne 0 ] || [ "$(cat "$small_exit")" != 0 ]; then
    echo 'persistent debug copy failed or held its output open:' >&2
    cat "$small_debug" >&2
    exit 1
fi

printf 'case: existing small files skip TCP setup and SSH data sessions\n'
for small_case in unchanged updated; do
    small_results="/tmp/syq-real-ssh-small-$small_case.ndjson"
    if [ "$small_case" = updated ]; then
        printf 'changed payload\n' >>"$small_source"
    fi
    if ! SYQ_DEBUG=1 syq cp --if-exists=update --no-progress --results "$small_results" \
        "$small_source" --to source --into /tmp/syq-real-ssh/small-destination \
        2>"$small_debug"; then
        cat "$small_debug" >&2
        exit 1
    fi
    small_status=$(tail -n 1 "$small_results")
    case "$small_status" in
        *'"status":"success"'*'"type":"result"'*) ;;
        *) cat "$small_results" "$small_debug" >&2; exit 1 ;;
    esac
    case "$small_case:$small_status" in
        unchanged:*'"files_unchanged":1'*|updated:*'"files_transferred":1'*) ;;
        *) cat "$small_results" >&2; exit 1 ;;
    esac
    if ! grep -q 'small copy: published' "$small_debug" ||
        grep -q 'TCP route probes started' "$small_debug" ||
        ! grep -q 'OpenSSH_' "$small_debug"; then
        cat "$small_debug" >&2
        exit 1
    fi
    small_expected=$(sha256sum "$small_source" | cut -d ' ' -f 1)
    small_actual=$(ssh source 'sha256sum /tmp/syq-real-ssh/small-destination/syq-real-ssh-small.bin' | cut -d ' ' -f 1)
    test "$small_expected" = "$small_actual"
done

printf 'case: restricted copies refuse an SSH control-plane destination\n'
make_tree source /tmp/syq-real-ssh/protected-source protected
# A refused destination leaves no enrollment on either machine.
protected_server_state='cat ~/.ssh/authorized_keys 2>/dev/null; find ~/.local/share/syq/enrollments -mindepth 1 -maxdepth 1 2>/dev/null | sort'
# shellcheck disable=SC2029
protected_server_before=$(ssh destination "$protected_server_state" | sha256sum)
protected_local_before=$(find "$home/.local/state/syq/enrollments" -mindepth 1 -maxdepth 1 2>/dev/null | sort | sha256sum)
# The laptop expands a leading ~ with the server's home, so it stays literal.
# shellcheck disable=SC2088
for protected_destination in /home/syq/.ssh/sender-controlled '~/.local/lib/syq/sender-controlled' .local/share/syq/enrollments/sender-controlled; do
    if protected_output=$(syq cp --no-progress --performance-tuning workers=2 --copy-metadata=permissions \
        --from source --srcs-in /tmp/syq-real-ssh/protected-source \
        --to destination --into "$protected_destination" 2>&1); then
        echo 'copy into the restricted receiver control plane unexpectedly succeeded' >&2
        exit 1
    fi
    case "$protected_output" in
        *"protected SSH configuration directory"*|*"protected store of syq executables"*|*"protected enrollment state directory"*) ;;
        *)
            echo 'control-plane refusal did not report the protected directory:' >&2
            printf '%s\n' "$protected_output" >&2
            exit 1
            ;;
    esac
    # shellcheck disable=SC2029
    ssh destination "cd && test ! -e $protected_destination"
done
# shellcheck disable=SC2029
test "$(ssh destination "$protected_server_state" | sha256sum)" = "$protected_server_before"
test "$(find "$home/.local/state/syq/enrollments" -mindepth 1 -maxdepth 1 2>/dev/null | sort | sha256sum)" = "$protected_local_before"
# Released versions' state is never created.
ssh destination '
    test ! -e ~/.local/share/syq/restricted
    test ! -e ~/.local/libexec/syq-receiver
'

python3 /usr/local/libexec/syq-test-restricted-mapping.py

printf 'case: small server-to-server copy to a restricted destination takes one turn\n'
# A restricted receiver serves the one-turn path too: a new file, an
# unchanged one and an updated one, with the receiver's results.
restricted_small=/tmp/syq-real-ssh/restricted-small-destination
restricted_small_source=/tmp/syq-real-ssh/restricted-small.bin
small_debug=/tmp/syq-real-ssh-restricted-small.debug
# shellcheck disable=SC2029
ssh source "mkdir -p /tmp/syq-real-ssh && head -c 2048 /dev/urandom >$restricted_small_source"
# shellcheck disable=SC2029
ssh destination "rm -rf $restricted_small && install -d $restricted_small"
for small_case in new unchanged updated; do
    small_results="/tmp/syq-real-ssh-restricted-small-$small_case.ndjson"
    if [ "$small_case" = updated ]; then
        # shellcheck disable=SC2029
        ssh source "printf 'changed payload\\n' >>$restricted_small_source"
    fi
    if ! SYQ_DEBUG=1 syq cp --if-exists=update --no-progress --results "$small_results" \
        --from source "$restricted_small_source" --to destination --into "$restricted_small" \
        2>"$small_debug"; then
        cat "$small_debug" >&2
        exit 1
    fi
    small_status=$(tail -n 1 "$small_results")
    case "$small_status" in
        *'"status":"success"'*) ;;
        *) cat "$small_results" "$small_debug" >&2; exit 1 ;;
    esac
    case "$small_case:$small_status" in
        new:*'"files_transferred":1'*|unchanged:*'"files_unchanged":1'*) ;;
        updated:*'"files_transferred":1'*) ;;
        *) cat "$small_results" >&2; exit 1 ;;
    esac
    if ! grep -q 'small copy: published' "$small_debug" ||
        ! grep -q 'syq-receiver\|restricted' "$small_debug"; then
        echo 'small copy to a restricted destination did not use the one-turn path:' >&2
        cat "$small_debug" >&2
        exit 1
    fi
    # shellcheck disable=SC2029
    small_expected=$(ssh source "sha256sum $restricted_small_source" | cut -d ' ' -f 1)
    # shellcheck disable=SC2029
    small_actual=$(ssh destination "sha256sum $restricted_small/restricted-small.bin" | cut -d ' ' -f 1)
    test "$small_expected" = "$small_actual"
done

printf 'case: a copy between two servers started here takes 1,024 named sources\n'
# Short paths fit the source's command line; 1,024 of about 175 bytes need
# twice its 128 KiB, so they go to the source over the connection instead.
many=/tmp/syq-real-ssh/many-sources
long_stem=$(printf 'n%.0s' $(seq 1 140))
# shellcheck disable=SC2029
ssh source "rm -rf $many && mkdir -p $many/short $many/long && cd $many/short && seq -f 'f%04g' 1 1025 | xargs touch && cd $many/long && seq -f '${long_stem}_%04g' 1 1024 | xargs touch"
for many_case in short long; do
    # shellcheck disable=SC2029
    ssh destination "rm -rf $many-$many_case && install -d $many-$many_case"
    many_results="/tmp/syq-real-ssh-many-$many_case.ndjson"
    if [ "$many_case" = short ]; then
        # shellcheck disable=SC2046
        set -- $(seq -f "$many/short/f%04g" 1 1024)
    else
        # shellcheck disable=SC2046
        set -- $(seq -f "$many/long/${long_stem}_%04g" 1 1024)
    fi
    if ! many_output=$(syq cp --no-progress --results "$many_results" --from source "$@" \
        --to destination --into "$many-$many_case" 2>&1); then
        printf '%s\n' "$many_output" >&2
        exit 1
    fi
    python3 - "$many_results" <<'PYTHON'
import json, sys
result = [json.loads(line) for line in open(sys.argv[1])][-1]
assert result["type"] == "result" and result["status"] == "success", result
assert result["files_transferred"] == 1024 and result["errors"] == 0, result
PYTHON
    # shellcheck disable=SC2029
    test "$(ssh destination "find $many-$many_case -type f | wc -l")" -eq 1024
done
# More than one copy accepts are refused before anything is set up.
# shellcheck disable=SC2046
set -- $(seq -f "$many/short/f%04g" 1 1025)
if many_output=$(syq cp --no-progress --from source "$@" --to destination --into "$many-short" 2>&1); then
    echo 'a copy between two servers with 1,025 sources unexpectedly started' >&2
    exit 1
fi
case "$many_output" in
    'syq: this copy names 1025 sources, more than the 1024 one copy accepts;'*) ;;
    *) printf '%s\n' "$many_output" >&2; exit 1 ;;
esac
# So is a command longer than its signature covers: 1,024 paths of about
# 290 bytes.
# shellcheck disable=SC2046
set -- $(seq -f "$many/huge/$(printf 'n%.0s' $(seq 1 250))_%04g" 1 1024)
if many_output=$(syq cp --no-progress --from source "$@" --to destination --into "$many-short" 2>&1); then
    echo 'a copy between two servers with a 290 KiB command unexpectedly started' >&2
    exit 1
fi
case "$many_output" in
    *'--peer-auth broker'*) printf '%s\n' "$many_output" >&2; exit 1 ;;
    'syq: this copy names 1024 sources, which make its command '*' KiB, more than the 256 KiB its approval can carry;'*) ;;
    *) printf '%s\n' "$many_output" >&2; exit 1 ;;
esac
set --

printf 'case: --follow-dst copies into the directory a restricted destination link leads to\n'
# The receiver resolves the link, wherever it leads as the account would
# follow it, and writes into the directory it leads to; the link stays a link.
make_tree source /tmp/syq-real-ssh/follow-source follow
ssh destination 'rm -rf /tmp/syq-real-ssh/follow-real /tmp/syq-real-ssh/follow-link &&
    install -d /tmp/syq-real-ssh/follow-real &&
    ln -s follow-real /tmp/syq-real-ssh/follow-link'
syq cp --no-progress --copy-metadata=permissions --follow-dst \
    --from source --srcs-in /tmp/syq-real-ssh/follow-source \
    --to destination --into /tmp/syq-real-ssh/follow-link
assert_same_tree source /tmp/syq-real-ssh/follow-source \
    destination /tmp/syq-real-ssh/follow-real follow
ssh destination 'test -L /tmp/syq-real-ssh/follow-link'
if follow_output=$(syq cp --no-progress --follow-dst --widen-dirs=all \
    --from source --srcs-in /tmp/syq-real-ssh/follow-source \
    --to destination --into /tmp/syq-real-ssh/follow-link 2>&1); then
    echo '--follow-dst with --widen-dirs all unexpectedly succeeded' >&2
    exit 1
fi
case "$follow_output" in
    *'--widen-dirs all cannot be combined with --follow-dst'*) ;;
    *) printf '%s\n' "$follow_output" >&2; exit 1 ;;
esac
# A link that leads outside the destination's directory is followed too, but
# not into the account's SSH configuration, however the link names it.
ssh destination 'rm -rf /tmp/syq-real-ssh-follow-outside /tmp/syq-real-ssh/follow-away \
        /tmp/syq-real-ssh/follow-ssh &&
    install -d /tmp/syq-real-ssh-follow-outside &&
    ln -s ../syq-real-ssh-follow-outside /tmp/syq-real-ssh/follow-away &&
    ln -s "$HOME/.ssh" /tmp/syq-real-ssh/follow-ssh'
syq cp --no-progress --copy-metadata=permissions --follow-dst \
    --from source --srcs-in /tmp/syq-real-ssh/follow-source \
    --to destination --into /tmp/syq-real-ssh/follow-away
assert_same_tree source /tmp/syq-real-ssh/follow-source \
    destination /tmp/syq-real-ssh-follow-outside follow-away
ssh_before=$(ssh destination 'ls -a ~/.ssh')
if follow_output=$(syq cp --no-progress --follow-dst \
    --from source --srcs-in /tmp/syq-real-ssh/follow-source \
    --to destination --into /tmp/syq-real-ssh/follow-ssh 2>&1); then
    echo '--follow-dst into ~/.ssh through a link unexpectedly succeeded' >&2
    exit 1
fi
case "$follow_output" in
    *"receiver's protected SSH configuration"*) ;;
    *) printf '%s\n' "$follow_output" >&2; exit 1 ;;
esac
test "$(ssh destination 'ls -a ~/.ssh')" = "$ssh_before"

printf 'case: a restricted copy sends unencrypted TCP data only when its command asks\n'
# The coordinator on source asks the destination's receiver for a listener
# without encryption, which the receiver allows because the signed command
# passes --no-tcp-encryption.
make_tree source /tmp/syq-real-ssh/plain-source plain
ssh destination 'rm -rf /tmp/syq-real-ssh/plain-destination'
plain_output=$(syq cp -vv --no-progress --copy-metadata=permissions --no-tcp-encryption \
    --from source --srcs-in /tmp/syq-real-ssh/plain-source \
    --to destination --into /tmp/syq-real-ssh/plain-destination 2>&1) || {
    printf '%s\n' "$plain_output" >&2
    exit 1
}
case "$plain_output" in
    *'transport: unencrypted TCP planned'*) ;;
    *) printf '%s\n' "$plain_output" >&2; exit 1 ;;
esac
assert_same_tree source /tmp/syq-real-ssh/plain-source \
    destination /tmp/syq-real-ssh/plain-destination plain

printf 'case: a symlink named as a source needs --follow-src or --src-non-dir\n'
# The coordinator runs on the source server here, so its refusal must reach
# the runner before anything is created on the destination.
ssh source 'rm -rf /tmp/syq-real-ssh/named-link-source &&
    mkdir -p /tmp/syq-real-ssh/named-link-source/real &&
    printf "named link\n" > /tmp/syq-real-ssh/named-link-source/real/file &&
    ln -s real /tmp/syq-real-ssh/named-link-source/link'
ssh destination 'rm -rf /tmp/syq-real-ssh/named-link && mkdir /tmp/syq-real-ssh/named-link'
if named_link_output=$(syq cp --no-progress --from source \
    /tmp/syq-real-ssh/named-link-source/link \
    --to destination --into /tmp/syq-real-ssh/named-link/refused 2>&1); then
    echo 'a named source symlink was copied without --follow-src' >&2
    exit 1
fi
case "$named_link_output" in
    *'is a symlink; pass --follow-src'*'--src-non-dir'*) ;;
    *) printf '%s\n' "$named_link_output" >&2; exit 1 ;;
esac
ssh destination 'test ! -e /tmp/syq-real-ssh/named-link/refused'
syq cp --no-progress --from source --follow-src \
    /tmp/syq-real-ssh/named-link-source/link \
    --to destination --into /tmp/syq-real-ssh/named-link/followed
syq cp --no-progress --from source --src-non-dir \
    /tmp/syq-real-ssh/named-link-source/link \
    --to destination --into /tmp/syq-real-ssh/named-link/linked
ssh destination 'test -d /tmp/syq-real-ssh/named-link/followed/link &&
    test ! -L /tmp/syq-real-ssh/named-link/followed/link &&
    test "$(cat /tmp/syq-real-ssh/named-link/followed/link/file)" = "named link" &&
    test "$(readlink /tmp/syq-real-ssh/named-link/linked/link)" = real'

printf 'case: a restricted destination reports a missing --into parent once\n'
# The coordinator runs on the source server; the receiver refuses to create
# the missing parent, and the runner should see that one reason.
ssh source 'mkdir -p /tmp/syq-real-ssh && printf "x\n" >/tmp/syq-real-ssh/missing-parent.txt'
ssh destination 'rm -rf /tmp/syq-real-ssh/missing-parent'
for missing_mode in plain results; do
    missing_args=
    if [ "$missing_mode" = results ]; then
        missing_args="--results /tmp/syq-real-ssh-missing-parent.ndjson"
    fi
    # shellcheck disable=SC2086
    if missing_output=$(syq cp --no-progress $missing_args --from source \
        /tmp/syq-real-ssh/missing-parent.txt \
        --to destination --into /tmp/syq-real-ssh/missing-parent/sub 2>&1); then
        echo 'a copy into a missing parent unexpectedly succeeded' >&2
        exit 1
    fi
    case "$missing_output" in
        *'wire preamble'*|*'incompatible'*|*'what landed'*)
            printf '%s\n' "$missing_output" >&2; exit 1 ;;
        *'missing-parent does not exist; a restricted copy creates its destination'*'refused the copy'*'sent no results through source'*) ;;
        *) printf '%s\n' "$missing_output" >&2; exit 1 ;;
    esac
done
case "$(tail -n 1 /tmp/syq-real-ssh-missing-parent.ndjson)" in
    *'"status":"failed"'*) ;;
    *) cat /tmp/syq-real-ssh-missing-parent.ndjson >&2; exit 1 ;;
esac
ssh destination 'test ! -e /tmp/syq-real-ssh/missing-parent'

printf 'case: restricted copies accept --pscope\n'
# --pscope selects which local connections are kept; the receiver's own
# connection stays private to the copy.
make_tree source /tmp/syq-real-ssh/pscope-source pscope
limits_scope=$(syq persist on --ephemeral)
syq cp --no-progress --pscope "$limits_scope" --copy-metadata=permissions \
    --from source --srcs-in /tmp/syq-real-ssh/pscope-source \
    --to destination --into /tmp/syq-real-ssh/pscope-destination
syq persist off --pscope "$limits_scope" >/dev/null
assert_same_tree source /tmp/syq-real-ssh/pscope-source \
    destination /tmp/syq-real-ssh/pscope-destination pscope

printf 'case: login keys sign restricted copies\n'
python3 /usr/local/libexec/syq-test-receiver-keys.py

printf 'case: a copy started here updates a receiver of another build and runs once more\n'
# The laptop's record says the destination's receiver runs this build, as
# after restoring the laptop's state from a backup, but the lab's second
# build has updated the receiver since. The receiver refuses the copy for
# its build; syq updates it to this build and runs the copy once more,
# leaving nothing of the refused attempt in the results.
make_tree source /tmp/syq-real-ssh/rebuild-source rebuild
syq cp --no-progress --from source --srcs-in /tmp/syq-real-ssh/rebuild-source \
    --to destination --into /tmp/syq-real-ssh/rebuild-first
rebuild_record=$(python3 - <<'PYTHON'
import json
from pathlib import Path
found = [path.parent for path in Path.home().glob(".local/state/syq/enrollments/*/enrollment.json")
         if (lambda record: (record["host"], record.get("port"), record["target_login"])
             == ("destination", None, "syq"))(json.loads(path.read_text()))]
assert len(found) == 1, found
print(found[0])
PYTHON
)
cp "$rebuild_record/enrollment.json" /tmp/syq-real-ssh-rebuild-enrollment.json
syq-other-build receiver enroll destination >/dev/null
test "$(syq-other-build receiver list | awk -F '\t' '$3 == "syq@destination" { print $4 }')" = \
    "$(syq-other-build --build-identity)"
cp /tmp/syq-real-ssh-rebuild-enrollment.json "$rebuild_record/enrollment.json"
ssh destination 'rm -rf /tmp/syq-real-ssh/rebuild-destination'
rm -f /tmp/syq-real-ssh-rebuild.ndjson
rebuild_output=$(syq cp --no-progress --results /tmp/syq-real-ssh-rebuild.ndjson \
    --from source --srcs-in /tmp/syq-real-ssh/rebuild-source \
    --to destination --into /tmp/syq-real-ssh/rebuild-destination 2>&1) || {
    printf '%s\n' "$rebuild_output" >&2
    exit 1
}
case "$rebuild_output" in
    *'runs another syq build than this one; updating it to this build and trying once more'*) ;;
    *) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
esac
assert_same_tree source /tmp/syq-real-ssh/rebuild-source \
    destination /tmp/syq-real-ssh/rebuild-destination rebuild
test "$(syq receiver list | awk -F '\t' '$3 == "syq@destination" { print $4 }')" = \
    "$(syq --build-identity)"
python3 - /tmp/syq-real-ssh-rebuild.ndjson <<'PYTHON'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1])]
kinds = [record["type"] for record in records]
assert kinds.count("run") == 1 and "error" not in kinds, records
assert records[-1]["type"] == "result" and records[-1]["status"] == "success", records[-1]
PYTHON

printf 'case: enrollment revocation stops active restricted receivers\n'
python3 /usr/local/libexec/syq-test-receiver-revoke.py

printf 'case: ending the requesting syq stops its server-to-server copy\n'
python3 /usr/local/libexec/syq-test-requester-loss.py

printf 'case: a detached restricted copy outlives the command that started it\n'
python3 /usr/local/libexec/syq-test-requester-loss.py detached

printf 'case: source coordinator with constrained agent and restricted destination\n'
make_tree source /tmp/syq-real-ssh/direct-source direct
# Exercise explicit congestion selection without requiring the CI kernel to
# permit cubic. Both endpoints run as an unprivileged user.
source_congestion=$(ssh source 'cat /proc/sys/net/ipv4/tcp_allowed_congestion_control')
destination_congestion=$(ssh destination 'cat /proc/sys/net/ipv4/tcp_allowed_congestion_control')
shared_congestion=
for algorithm in $source_congestion; do
    case " $destination_congestion " in
        *" $algorithm "*) shared_congestion=$algorithm; break ;;
    esac
done
if [ -z "$shared_congestion" ]; then
    printf 'no shared allowed TCP congestion algorithm: source=%s destination=%s\n' \
        "$source_congestion" "$destination_congestion" >&2
    exit 1
fi
printf 'explicit TCP congestion algorithm: %s\n' "$shared_congestion"
syq cp --no-progress --performance-tuning workers=2 --copy-metadata=permissions --tcp-congestion "$shared_congestion" \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
assert_same_tree \
    source /tmp/syq-real-ssh/direct-source \
    destination /tmp/syq-real-ssh/direct-destination \
    direct

printf 'case: a killed copy leaves a restricted receiver only partials worth resuming\n'
# Partials written in ranges at a low capped rate stay on the receiver, and
# unfinished, for tens of seconds. Killing the source coordinator, the
# newest syq on the source, ends the command-restricted receiver's control
# connection: the receiver removes the partial shorter than 1 MiB and keeps
# the longer one for resuming.
killed_root=/tmp/syq-real-ssh/killed-destination
ssh source 'mkdir -p /tmp/syq-real-ssh/killed-source &&
    head -c 921600 /dev/urandom >/tmp/syq-real-ssh/killed-source/short &&
    head -c 6291456 /dev/urandom >/tmp/syq-real-ssh/killed-source/long'
killed_partials() {
    # shellcheck disable=SC2029
    ssh destination "find $killed_root -maxdepth 1 -type f -name '.*.syq-tmp.*' -printf '%f %s\\n' 2>/dev/null | sort"
}
wait_for_killed_partials() {
    wanted=$1
    deadline=$(($(date +%s) + 30))
    next_progress=$(($(date +%s) + 5))
    while :; do
        listing=$(killed_partials)
        if [ "$(printf '%s' "$listing" | grep -c .)" -eq "$wanted" ]; then
            break
        fi
        now=$(date +%s)
        if [ "$now" -ge "$deadline" ]; then
            printf 'timed out waiting for %s partials; found:\n%s\n' "$wanted" "$listing" >&2
            exit 1
        fi
        if [ "$now" -ge "$next_progress" ]; then
            printf 'waiting for %s partials; found:\n%s\n' "$wanted" "$listing" >&2
            next_progress=$((now + 5))
        fi
        sleep 0.2
    done
}
syq cp --no-progress --resource-limits bandwidth=32 \
    --performance-tuning workers=2,copy-path=ranges \
    --from source --srcs-in /tmp/syq-real-ssh/killed-source \
    --to destination --into "$killed_root" &
killed_copy_pid=$!
wait_for_killed_partials 2
ssh source 'pkill -KILL -n -x syq'
if wait "$killed_copy_pid"; then
    echo 'a copy whose coordinator was killed reported success' >&2
    exit 1
fi
wait_for_killed_partials 1
# shellcheck disable=SC2029
test "$(ssh destination "find $killed_root -maxdepth 1 -type f -name '.long.syq-tmp.*' -size 6291456c" | grep -c .)" -eq 1
# shellcheck disable=SC2029
ssh destination "test ! -e $killed_root/short && test ! -e $killed_root/long"
syq cp --no-progress --from source --srcs-in /tmp/syq-real-ssh/killed-source \
    --to destination --into "$killed_root"
for name in short long; do
    # shellcheck disable=SC2029
    ssh source "sha256sum </tmp/syq-real-ssh/killed-source/$name" >/tmp/syq-killed-source.sum
    # shellcheck disable=SC2029
    ssh destination "sha256sum <$killed_root/$name" | cmp - /tmp/syq-killed-source.sum
done

printf 'case: native remote removal follows parents but preserves final link identity\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/rm-policy/real; printf keep > /tmp/syq-real-ssh/rm-policy/real/file; ln -s real /tmp/syq-real-ssh/rm-policy/link'
syq rm --on source --root /tmp/syq-real-ssh/rm-policy --follow-src --src-non-dir link
ssh source 'test ! -L /tmp/syq-real-ssh/rm-policy/link; test "$(cat /tmp/syq-real-ssh/rm-policy/real/file)" = keep; ln -s real /tmp/syq-real-ssh/rm-policy/link'
policy_status=0
syq rm --on source --root /tmp/syq-real-ssh/rm-policy --follow-src --srcs-in link || policy_status=$?
test "$policy_status" -ne 0
ssh source 'test -f /tmp/syq-real-ssh/rm-policy/real/file'
syq rm --on source --root /tmp/syq-real-ssh/rm-policy --follow-src link/file
ssh source 'test -L /tmp/syq-real-ssh/rm-policy/link; test ! -e /tmp/syq-real-ssh/rm-policy/real/file'

printf 'case: native remote removal requires explicit tree selection\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/rm-policy/tree/nested; printf keep > /tmp/syq-real-ssh/rm-policy/tree/nested/child; printf keep > /tmp/syq-real-ssh/rm-policy/victim'
policy_status=0
syq rm --on source --root /tmp/syq-real-ssh/rm-policy victim tree || policy_status=$?
test "$policy_status" -ne 0
ssh source 'test -f /tmp/syq-real-ssh/rm-policy/victim; test -f /tmp/syq-real-ssh/rm-policy/tree/nested/child'
syq rm --on source --root /tmp/syq-real-ssh/rm-policy --srcs-in tree
ssh source 'test -d /tmp/syq-real-ssh/rm-policy/tree; test ! -e /tmp/syq-real-ssh/rm-policy/tree/nested'
syq rm --on source --root /tmp/syq-real-ssh/rm-policy --src-dir tree
ssh source 'test ! -e /tmp/syq-real-ssh/rm-policy/tree'

printf 'case: comparison results and restricted receiver overwrite policies\n'
syq cp --dry-run --hash --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination --coordinate-at local \
    --results /tmp/syq-matching-preview.ndjson
assert_preview_counts /tmp/syq-matching-preview.ndjson 0 2
ssh source 'printf source > /tmp/syq-real-ssh/direct-source/policy-file; printf new > /tmp/syq-real-ssh/direct-source/policy-new'
ssh destination 'printf destination > /tmp/syq-real-ssh/direct-destination/policy-file'
ssh source 'mkdir -p /tmp/syq-real-ssh/direct-source/policy-dir/new; chmod 750 /tmp/syq-real-ssh/direct-source/policy-dir /tmp/syq-real-ssh/direct-source/policy-dir/new'
ssh destination 'mkdir -p /tmp/syq-real-ssh/direct-destination/policy-dir; chmod 711 /tmp/syq-real-ssh/direct-destination/policy-dir'

syq cp --if-exists=keep --copy-metadata=permissions --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = destination; test "$(cat /tmp/syq-real-ssh/direct-destination/policy-new)" = new; rm /tmp/syq-real-ssh/direct-destination/policy-new'
ssh destination 'test "$(stat -c %a /tmp/syq-real-ssh/direct-destination/policy-dir)" = 711; test "$(stat -c %a /tmp/syq-real-ssh/direct-destination/policy-dir/new)" = 750'

syq cp --if-exists=update --only-existing --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = source; test ! -e /tmp/syq-real-ssh/direct-destination/policy-new'
syq cp --dry-run --hash --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination --coordinate-at local \
    --results /tmp/syq-missing-preview.ndjson
assert_preview_counts /tmp/syq-missing-preview.ndjson 1 3
ssh destination 'test ! -e /tmp/syq-real-ssh/direct-destination/policy-new'
ssh source 'touch -m -d @1600000000 /tmp/syq-real-ssh/direct-source/policy-file'
ssh destination 'printf newer > /tmp/syq-real-ssh/direct-destination/policy-file; touch -m -d @1700000000 /tmp/syq-real-ssh/direct-destination/policy-file'
syq cp --if-exists=update-if-older --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = newer; test -e /tmp/syq-real-ssh/direct-destination/policy-new'

printf 'case: results of server-to-server copies on every route\n'
python3 /usr/local/libexec/syq-test-results-stream.py

printf 'case: restricted receiver prunes without a stated deletion limit\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/prune-source && printf kept > /tmp/syq-real-ssh/prune-source/kept'
ssh destination 'mkdir -p /tmp/syq-real-ssh/prune-destination && printf extra > /tmp/syq-real-ssh/prune-destination/extra && printf extra > /tmp/syq-real-ssh/prune-destination/other'
syq cp --prune --no-progress --performance-tuning workers=2 \
    --from source --srcs-in /tmp/syq-real-ssh/prune-source \
    --to destination --into-existing /tmp/syq-real-ssh/prune-destination
ssh destination 'cd /tmp/syq-real-ssh/prune-destination && test ! -e extra && test ! -e other && test "$(cat kept)" = kept'

printf 'case: restricted receiver stages an --as-new file under --in-place=new\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/inplace-policy-source && printf new > /tmp/syq-real-ssh/inplace-policy-source/b'
ssh destination 'mkdir -p /tmp/syq-real-ssh/inplace-policy'
syq cp --in-place=new --no-progress --from source --src /tmp/syq-real-ssh/inplace-policy-source/b \
    --to destination --as-new /tmp/syq-real-ssh/inplace-policy/created
ssh destination 'test "$(cat /tmp/syq-real-ssh/inplace-policy/created)" = new'
# A name that exists is refused and keeps its contents.
ssh destination 'printf theirs > /tmp/syq-real-ssh/inplace-policy/taken'
if taken_output=$(syq cp --in-place=new --no-progress --from source --src /tmp/syq-real-ssh/inplace-policy-source/b \
    --to destination --as-new /tmp/syq-real-ssh/inplace-policy/taken 2>&1); then
    printf 'an --in-place=new --as-new copy onto an existing name unexpectedly succeeded:\n%s\n' "$taken_output" >&2
    exit 1
fi
ssh destination 'test "$(cat /tmp/syq-real-ssh/inplace-policy/taken)" = theirs'

printf 'case: restricted receiver replaces each name of a linked destination\n'
# Eight names of one destination file. The odd names' sources changed in
# their second block; the even names' did not, but their times differ. The
# receiver changes nothing in a file with other names, so each name is
# replaced by a file of its own, built from the old one: a changed name is
# sent only its second block, an unchanged one nothing.
ssh source python3 - <<'PY_LINKED_SOURCE'
import os
root = '/tmp/syq-real-ssh/linked-source'
os.makedirs(root)
block = 64 * 1024
old = bytes(i % 251 for i in range(2 * block))
new = old[:block] + bytes([7]) * block
for i in range(8):
    path = f'{root}/name{i}'
    with open(path, 'wb') as f:
        f.write(new if i % 2 else old)
    mtime = 1_600_000_000 + (i if i % 2 else 0)
    os.utime(path, (mtime, mtime))
PY_LINKED_SOURCE
# One worker, and then four at once, whose requests reach the receiver
# interleaved. Each name is compared once, and each changed name is sent
# only its second block. Last, the names are copied whole, several to a
# request, into a destination of another size.
for linked_run in 1 4 whole; do
    linked_size=2
    linked_workers=$linked_run
    if [ "$linked_run" = whole ]; then
        linked_size=3
        linked_workers=4
    fi
    # The fixture path is fixed; only the size comes from this loop.
    # shellcheck disable=SC2029
    ssh destination "python3 - $linked_size" <<'PY_LINKED_DESTINATION'
import os, shutil, sys
root = '/tmp/syq-real-ssh/linked-destination'
shutil.rmtree(root, ignore_errors=True)
os.makedirs(root)
block = 64 * 1024
first = f'{root}/name0'
with open(first, 'wb') as f:
    f.write(bytes(i % 251 for i in range(int(sys.argv[1]) * block)))
os.utime(first, (1_500_000_000, 1_500_000_000))
for i in range(1, 8):
    os.link(first, f'{root}/name{i}')
with open('/tmp/syq-real-ssh/linked-inode', 'w') as f:
    f.write(str(os.stat(first).st_ino))
PY_LINKED_DESTINATION
    linked_results=/tmp/syq-real-ssh-linked.ndjson
    linked_debug=/tmp/syq-real-ssh-linked.debug
    rm -f "$linked_results"
    if ! SYQ_DEBUG=1 syq cp --copy-metadata=mtime --no-progress \
        --performance-tuning "workers=$linked_workers" --results "$linked_results" \
        --from source --srcs-in /tmp/syq-real-ssh/linked-source \
        --to destination --into /tmp/syq-real-ssh/linked-destination \
        2>"$linked_debug"; then
        cat "$linked_debug" >&2
        exit 1
    fi
    python3 - "$linked_results" "$linked_debug" "$linked_run" <<'PY_LINKED_RESULTS'
import json, sys
from pathlib import Path
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert records[-1]['type'] == 'result' and records[-1]['status'] == 'success', records
assert records[-1]['errors'] == 0, records[-1]
if sys.argv[3] != 'whole':
    assert records[-1]['bytes_transferred'] == 4 * 65536, records[-1]
    marker = 'syq: tuning observed: '
    observed = [
        json.loads(line.split(marker, 1)[1])
        for line in Path(sys.argv[2]).read_text().splitlines()
        if marker in line
    ]
    assert any(
        (counts.get('compared_files'), counts.get('kept_files'), counts.get('patched_files')) == (8, 0, 8)
        for counts in observed
    ), observed
PY_LINKED_RESULTS
    # shellcheck disable=SC2029
    ssh destination "python3 - $linked_run" <<'PY_LINKED_CHECK'
import os, sys
root = '/tmp/syq-real-ssh/linked-destination'
inode = int(open('/tmp/syq-real-ssh/linked-inode').read())
block = 64 * 1024
old = bytes(i % 251 for i in range(2 * block))
new = old[:block] + bytes([7]) * block
replaced = set()
for i in range(8):
    path = f'{root}/name{i}'
    status = os.stat(path)
    with open(path, 'rb') as f:
        contents = f.read()
    # Each name names a new file of its own.
    assert contents == (new if i % 2 else old) and status.st_ino != inode, (i, status)
    assert status.st_ino not in replaced and status.st_nlink == 1, (i, status)
    replaced.add(status.st_ino)
    assert int(status.st_mtime) == 1_600_000_000 + (i if i % 2 else 0), (i, status)
PY_LINKED_CHECK
done

printf 'case: ordinary and restricted receivers choose the same modes\n'
# The same tree on the runner and on the source: the runner copies it through
# an ordinary SSH helper, with its own umask narrower than the destination's,
# and the source through the destination's restricted receiver.
mode_tree=$(cat <<'PY_MODE_TREE'
import os, sys
root = sys.argv[1]
os.makedirs(root)
for name, mode in [('new-dir', 0o755), ('read-only-dir', 0o555), ('private-dir', 0o700),
                   ('sticky-dir', 0o1777), ('existing-dir', 0o777)]:
    os.mkdir(f'{root}/{name}')
    with open(f'{root}/{name}/file', 'wb') as f:
        f.write(name.encode())
    os.chmod(f'{root}/{name}', mode)
for name, mode, size in [('script', 0o755, 7), ('secret', 0o600, 7), ('read-only', 0o444, 7),
                         ('setuid', 0o4755, 7), ('existing', 0o644, 9),
                         ('large', 0o640, 5 << 20), ('large-read-only', 0o444, 5 << 20)]:
    with open(f'{root}/{name}', 'wb') as f:
        f.write(bytes([len(name)]) * size)
    os.chmod(f'{root}/{name}', mode)
PY_MODE_TREE
)
printf '%s\n' "$mode_tree" | python3 - /tmp/syq-real-ssh-mode-tree
printf '%s\n' "$mode_tree" | ssh source python3 - /tmp/syq-real-ssh/mode-tree
for mode_variant in default permissions inplace; do
    set --
    case "$mode_variant" in
        permissions) set -- --copy-metadata=permissions ;;
        inplace) set -- --in-place=new ;;
    esac
    for mode_receiver in ordinary restricted; do
        mode_destination=/tmp/syq-real-ssh/modes-$mode_variant-$mode_receiver
        # The fixture path is set by this loop.
        # shellcheck disable=SC2029
        ssh destination "mkdir -m 2775 $mode_destination && mkdir -m 0750 $mode_destination/existing-dir && printf old > $mode_destination/existing && chmod 0600 $mode_destination/existing"
        if [ "$mode_receiver" = ordinary ]; then
            (umask 077; syq cp "$@" --no-progress --performance-tuning workers=4 \
                --srcs-in /tmp/syq-real-ssh-mode-tree --to destination --into "$mode_destination")
        else
            syq cp "$@" --no-progress --performance-tuning workers=4 \
                --from source --srcs-in /tmp/syq-real-ssh/mode-tree \
                --to destination --into "$mode_destination"
        fi
    done
    # shellcheck disable=SC2029
    ssh destination "python3 - $mode_variant" <<'PY_MODE_CHECK'
import os, sys
variant = sys.argv[1]
def modes(root):
    found = {}
    for directory, names, files in os.walk(root):
        for name in names + files:
            path = os.path.join(directory, name)
            found[os.path.relpath(path, root)] = os.lstat(path).st_mode & 0o7777
    found['.'] = os.lstat(root).st_mode & 0o7777
    return found
base = f'/tmp/syq-real-ssh/modes-{variant}'
ordinary, restricted = modes(f'{base}-ordinary'), modes(f'{base}-restricted')
assert ordinary == restricted, (ordinary, restricted)
if variant != 'permissions':
    # Without -p: the destination's umask (022), not the runner's (077);
    # existing entries keep their modes; no special bits from the source;
    # new directories keep owner access and inherit the setgid bit.
    expected = {
        '.': 0o2775, 'existing': 0o600, 'existing-dir': 0o2750,
        'script': 0o755, 'secret': 0o600, 'read-only': 0o444, 'setuid': 0o755,
        'large': 0o640, 'large-read-only': 0o444,
        'new-dir': 0o2755, 'read-only-dir': 0o2755, 'private-dir': 0o2700,
        'sticky-dir': 0o2755,
    }
    for name, mode in expected.items():
        assert ordinary[name] == mode, (name, oct(ordinary[name]), oct(mode))
PY_MODE_CHECK
done

# A new --into directory, like a new parent, gets 0777 limited by the
# destination's umask (022 here), not the runner's (077), on both receivers.
for mode_receiver in ordinary restricted; do
    mode_root=/tmp/syq-real-ssh/modes-new-root-$mode_receiver
    # shellcheck disable=SC2029
    ssh destination "rm -rf $mode_root && mkdir $mode_root"
    if [ "$mode_receiver" = ordinary ]; then
        (umask 077; syq cp --no-progress --srcs-in /tmp/syq-real-ssh-mode-tree \
            --to destination --into "$mode_root/new")
    else
        syq cp --no-progress --from source --srcs-in /tmp/syq-real-ssh/mode-tree \
            --to destination --into "$mode_root/new"
    fi
    # shellcheck disable=SC2029
    test "$(ssh destination "stat -c %a $mode_root/new")" = 755
done

printf 'case: ordinary and restricted receivers update the same files in place\n'
# Under --in-place=update both receivers write a file of their own with one
# name where it is, and replace one with another name and one more widely
# readable than the copy leaves it; each copy says so.
update_tree=$(cat <<'PY_UPDATE_TREE'
import os, sys
root = sys.argv[1]
os.makedirs(root)
for name, mode in [('mine', 0o644), ('linked', 0o644), ('wider', 0o600)]:
    with open(f'{root}/{name}', 'wb') as f:
        f.write(bytes(range(256)) * 4096)
    os.chmod(f'{root}/{name}', mode)
    os.utime(f'{root}/{name}', (1_700_000_000, 1_700_000_000))
PY_UPDATE_TREE
)
printf '%s\n' "$update_tree" | python3 - /tmp/syq-real-ssh-update-tree
printf '%s\n' "$update_tree" | ssh source python3 - /tmp/syq-real-ssh/update-tree
for update_receiver in ordinary restricted; do
    update_destination=/tmp/syq-real-ssh/update-$update_receiver
    # The fixture path is set by this loop.
    # shellcheck disable=SC2029
    ssh destination "python3 - $update_destination" <<'PY_UPDATE_DESTINATION'
import json, os, sys
root = sys.argv[1]
os.makedirs(root)
inodes = {}
for name in ['mine', 'linked', 'wider']:
    data = bytearray(bytes(range(256)) * 4096)
    data[1000] ^= 1
    with open(f'{root}/{name}', 'wb') as f:
        f.write(data)
    os.chmod(f'{root}/{name}', 0o644)
    inodes[name] = os.stat(f'{root}/{name}').st_ino
os.link(f'{root}/linked', f'{root}.outside')
with open(f'{root}.inodes', 'w') as f:
    json.dump(inodes, f)
PY_UPDATE_DESTINATION
    if [ "$update_receiver" = ordinary ]; then
        update_output=$(syq cp --in-place=update --copy-metadata=permissions --no-progress \
            --srcs-in /tmp/syq-real-ssh-update-tree --to destination --into "$update_destination")
    else
        update_output=$(syq cp --in-place=update --copy-metadata=permissions --no-progress \
            --from source --srcs-in /tmp/syq-real-ssh/update-tree \
            --to destination --into "$update_destination")
    fi
    case "$update_output" in
        *'replaced 2 existing files instead of updating them in place: 1 with other hard links, 1 with wider permissions'*) ;;
        *)
            printf 'the %s copy did not report its replacements:\n%s\n' "$update_receiver" "$update_output" >&2
            exit 1
            ;;
    esac
    # shellcheck disable=SC2029
    ssh destination "python3 - $update_destination" <<'PY_UPDATE_CHECK'
import json, os, sys
root = sys.argv[1]
with open(f'{root}.inodes') as f:
    inodes = json.load(f)
expected = bytes(range(256)) * 4096
for name, kept in [('mine', True), ('linked', False), ('wider', False)]:
    with open(f'{root}/{name}', 'rb') as f:
        assert f.read() == expected, name
    assert (os.stat(f'{root}/{name}').st_ino == inodes[name]) == kept, name
with open(f'{root}.outside', 'rb') as f:
    assert f.read() != expected
PY_UPDATE_CHECK
done

printf 'case: expression selection on source, destination, and local coordinators\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/expressions/sub; printf selected > /tmp/syq-real-ssh/expressions/sub/keep; printf x > /tmp/syq-real-ssh/expressions/sub/tiny'
for coordinator in src dst local; do
    set --
    if [ "$coordinator" = dst ]; then set -- --peer-auth broker; fi
    syq cp "$@" --from source --srcs-in /tmp/syq-real-ssh/expressions \
        --to destination --into "/tmp/syq-real-ssh/expressions-$coordinator" \
        --coordinate-at "$coordinator" --no-progress \
        --where "src.kind = 'file' and src.size > 1B and src.path glob 'sub/*'" \
        --copy-if 'not dst.exists or src.size > dst.size'
    # Select the fixture path locally; read its contents on the destination.
    # shellcheck disable=SC2029
    ssh destination "test \"\$(cat /tmp/syq-real-ssh/expressions-$coordinator/sub/keep)\" = selected; test ! -e /tmp/syq-real-ssh/expressions-$coordinator/sub/tiny"
done

printf 'case: explicit file ignores on source, destination, and local coordinators\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/ignore-source; printf selected > /tmp/syq-real-ssh/ignore-source/report.txt'
for coordinator in src dst local; do
    set --
    if [ "$coordinator" = dst ]; then set -- --peer-auth broker; fi
    syq cp "$@" --from source /tmp/syq-real-ssh/ignore-source/report.txt \
        --to destination --as "/tmp/syq-real-ssh/ignore-$coordinator" \
        --coordinate-at "$coordinator" --no-progress --ignore '*.txt'
    # These paths are controlled fixtures selected by this loop.
    # shellcheck disable=SC2029
    ssh destination "test ! -e /tmp/syq-real-ssh/ignore-$coordinator"
    syq cp "$@" --from source /tmp/syq-real-ssh/ignore-source/report.txt \
        --to destination --as "/tmp/syq-real-ssh/ignore-$coordinator" \
        --coordinate-at "$coordinator" --no-progress --ignore '*.txt' --ignore '!report.txt'
    # shellcheck disable=SC2029
    ssh destination "test \"\$(cat /tmp/syq-real-ssh/ignore-$coordinator)\" = selected"
done

printf 'case: restricted expressions preserve container permissions and inheritance\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/expression-modes/new /tmp/syq-real-ssh/expression-modes/old; printf selected > /tmp/syq-real-ssh/expression-modes/new/keep; printf selected > /tmp/syq-real-ssh/expression-modes/old/keep; chmod 710 /tmp/syq-real-ssh/expression-modes/new'
for preservation in default permissions; do
    destination=/tmp/syq-real-ssh/expression-modes-$preservation
    # This controlled fixture path is set by the local loop.
    # shellcheck disable=SC2029
    ssh destination "mkdir -p $destination/old; chmod 2775 $destination; chmod 2555 $destination/old"
    set --
    if [ "$preservation" = permissions ]; then set -- --copy-metadata=permissions; fi
    syq cp --widen-dirs=rsync "$@" --from source --srcs-in /tmp/syq-real-ssh/expression-modes \
        --to destination --into "$destination" --coordinate-at src --no-progress \
        --where "src.kind = 'file'" --copy-if "src.kind != 'dir'"
    # Expand the fixture path locally; run cat and stat on the destination.
    # shellcheck disable=SC2029
    ssh destination "test \"\$(cat $destination/new/keep)\" = selected; test \"\$(cat $destination/old/keep)\" = selected; test \"\$(stat -c %a $destination/new)\" = 2755; test \"\$(stat -c %a $destination/old)\" = 2555"
done

printf 'case: destination firewall triggers automatic TCP fallback to SSH\n'
make_tree source /tmp/syq-real-ssh/firewall-source firewall
syq cp --no-progress --performance-tuning workers=2 --copy-metadata=permissions \
    --tcp-ports "$blocked_tcp_port-$blocked_tcp_port" \
    --from source --srcs-in /tmp/syq-real-ssh/firewall-source \
    --to destination --into /tmp/syq-real-ssh/firewall-destination \
    2>/tmp/syq-real-ssh-firewall.stderr
# The fallback is said once, with how to skip trying TCP.
if [ "$(grep -c 'sending file data over SSH instead.*--no-tcp' /tmp/syq-real-ssh-firewall.stderr)" != 1 ]; then
    cat /tmp/syq-real-ssh-firewall.stderr >&2
    exit 1
fi
assert_same_tree \
    source /tmp/syq-real-ssh/firewall-source \
    destination /tmp/syq-real-ssh/firewall-destination \
    firewall

printf 'case: source coordinator with constrained agent and SSH data channels\n'
make_tree source /tmp/syq-real-ssh/ssh-source ssh
syq cp --no-progress --no-tcp --performance-tuning workers=2 --copy-metadata=permissions \
    --from source --srcs-in /tmp/syq-real-ssh/ssh-source \
    --to destination --into /tmp/syq-real-ssh/ssh-destination
assert_same_tree \
    source /tmp/syq-real-ssh/ssh-source \
    destination /tmp/syq-real-ssh/ssh-destination \
    ssh

printf 'case: an unavailable direct SSH data route fails without relaying through the runner\n'
ssh source 'dd if=/dev/zero of=/tmp/syq-real-ssh/no-route-source bs=1048576 count=2 status=none; touch /tmp/syq-real-ssh-block-restricted-workers'
route_status=0
syq cp --no-progress --no-tcp --performance-tuning workers=1 \
    --from source /tmp/syq-real-ssh/no-route-source \
    --to destination --as /tmp/syq-real-ssh/no-route-destination || route_status=$?
ssh source 'rm -f /tmp/syq-real-ssh-block-restricted-workers /tmp/syq-real-ssh-block-restricted-workers.control'
test "$route_status" -ne 0
ssh destination 'test ! -e /tmp/syq-real-ssh/no-route-destination'

printf 'case: destination coordinator with the reversed constrained-agent edge\n'
make_tree source /tmp/syq-real-ssh/pull-source pull
syq cp --no-progress --no-tcp --performance-tuning workers=2 --copy-metadata=permissions \
    --peer-auth broker --coordinate-at dst \
    --from source --srcs-in /tmp/syq-real-ssh/pull-source \
    --to destination --into /tmp/syq-real-ssh/pull-destination
assert_same_tree \
    source /tmp/syq-real-ssh/pull-source \
    destination /tmp/syq-real-ssh/pull-destination \
    pull

printf 'case: local coordinator relaying between two SSH endpoints\n'
make_tree source /tmp/syq-real-ssh/relay-source relay
trace=/tmp/syq-real-ssh-ssh.trace
rm -f "$trace"
syq cp --no-progress --no-tcp --performance-tuning workers=2 --copy-metadata=permissions \
    --coordinate-at local \
    --from source --srcs-in /tmp/syq-real-ssh/relay-source \
    --to destination --into /tmp/syq-real-ssh/relay-destination

if [ "${SYQ_REAL_SSH_PROFILE:-default}" = max-sessions-1 ]; then
    test -s "$trace"
    rejected_multiplexed_attempts=$(awk -F '\t' '
        $1 == "phase=end" &&
        $3 == "host=destination" &&
        $4 == "control_master=no" &&
        $5 != "control_path=none" &&
        $5 != "control_path=unset" &&
        $6 == "control_socket=present" &&
        $7 == "strict_mux=yes" &&
        $8 == "status=255" { count++ }
        END { print count + 0 }
    ' "$trace")
    successful_independent_retries=$(awk -F '\t' '
        $1 == "phase=end" &&
        $3 == "host=destination" &&
        $4 == "control_master=no" &&
        $5 == "control_path=none" &&
        $7 == "strict_mux=no" &&
        $8 == "status=0" { count++ }
        END { print count + 0 }
    ' "$trace")
    if [ "$rejected_multiplexed_attempts" -lt 1 ] || [ "$successful_independent_retries" -lt 1 ]; then
        echo 'MaxSessions profile did not expose a multiplexed rejection and a successful independent retry:' >&2
        cat "$trace" >&2
        exit 1
    fi
    printf 'MaxSessions evidence: %s rejected multiplexed attempts, %s successful independent retries\n' \
        "$rejected_multiplexed_attempts" "$successful_independent_retries"
fi

assert_same_tree \
    source /tmp/syq-real-ssh/relay-source \
    destination /tmp/syq-real-ssh/relay-destination \
    relay

printf 'case: tuning overrides for range uploads, downloads, direct copies, and relay\n'
tuning=copy-path=ranges,request-size=2M,pipeline-depth=64,split-min-size=8M,bw-pacing=average
dd if=/dev/urandom of=/tmp/syq-real-ssh-tuning.bin bs=1M count=9 status=none
for transport in tcp ssh; do
    if [ "$transport" = ssh ]; then
        set -- --no-tcp
    else
        set --
    fi
    syq cp /tmp/syq-real-ssh-tuning.bin --to source \
        --as "/tmp/syq-real-ssh/tuning-$transport" --performance-tuning workers=1 --no-progress \
        --resource-limits bandwidth=8M --performance-tuning "$tuning" "$@"
    syq cp --from source "/tmp/syq-real-ssh/tuning-$transport" \
        --as "/tmp/syq-real-ssh-tuning-$transport-download" --performance-tuning workers=1 --no-progress \
        --resource-limits bandwidth=8M --performance-tuning "$tuning" "$@"
    cmp /tmp/syq-real-ssh-tuning.bin "/tmp/syq-real-ssh-tuning-$transport-download"
done
for coordinator in src dst local; do
    case "$coordinator" in
        src) set -- ;;
        dst) set -- --peer-auth broker --no-tcp ;;
        local) set -- --no-tcp ;;
    esac
    syq cp --from source /tmp/syq-real-ssh/tuning-tcp --to destination \
        --as "/tmp/syq-real-ssh/tuning-$coordinator" --coordinate-at "$coordinator" \
        --performance-tuning workers=1 --no-progress --resource-limits bandwidth=8M --performance-tuning "$tuning" "$@"
    ssh destination sh -s -- "$coordinator" > /tmp/syq-real-ssh-tuning-check <<'EOF'
cat "/tmp/syq-real-ssh/tuning-$1"
EOF
    cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-tuning-check
done

printf 'case: restricted authorization accepts 128 workers\n'
syq cp --from source /tmp/syq-real-ssh/tuning-tcp --to destination \
    --as /tmp/syq-real-ssh/workers-128 --coordinate-at src \
    --performance-tuning workers=128 --no-progress
ssh destination cat /tmp/syq-real-ssh/workers-128 > /tmp/syq-real-ssh-workers-check
cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-workers-check

printf 'case: adaptive worker ceilings through each remote coordinator\n'
for transport in tcp ssh; do
    for coordinator in src dst local; do
        if [ "$transport" = ssh ]; then set -- --no-tcp; else set --; fi
        if [ "$coordinator" = dst ]; then set -- "$@" --peer-auth broker; fi
        syq cp --from source /tmp/syq-real-ssh/tuning-tcp --to destination \
            --as "/tmp/syq-real-ssh/limited-$transport-$coordinator" \
            --coordinate-at "$coordinator" --resource-limits workers=1 --no-progress -vv "$@"
        # These loop variables select the remote filename on the client.
        # shellcheck disable=SC2029
        ssh destination cat "/tmp/syq-real-ssh/limited-$transport-$coordinator" > /tmp/syq-real-ssh-limited-check
        cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-limited-check
    done
done

printf 'case: experimental streaming over TCP/SSH and each coordinator\n'
streaming=copy-path=streaming,request-size=128K,split-min-size=1M,bw-pacing=average
for transport in tcp ssh; do
    if [ "$transport" = ssh ]; then set -- --no-tcp; else set --; fi
    timeout --kill-after=5s 25s syq cp /tmp/syq-real-ssh-tuning.bin --to source \
        --as "/tmp/syq-real-ssh/streaming-$transport" --performance-tuning workers=2 --no-progress \
        --resource-limits bandwidth=8M --performance-tuning "$streaming" "$@"
    timeout --kill-after=5s 25s syq cp --from source "/tmp/syq-real-ssh/streaming-$transport" \
        --as "/tmp/syq-real-ssh-streaming-$transport-download" --performance-tuning workers=2 --no-progress \
        --resource-limits bandwidth=8M --performance-tuning "$streaming" "$@"
    cmp /tmp/syq-real-ssh-tuning.bin "/tmp/syq-real-ssh-streaming-$transport-download"
done
for coordinator in src dst local; do
    case "$coordinator" in
        src) set -- ;;
        dst) set -- --peer-auth broker --no-tcp ;;
        local) set -- --no-tcp ;;
    esac
    timeout --kill-after=5s 25s syq cp --from source /tmp/syq-real-ssh/streaming-tcp --to destination \
        --as "/tmp/syq-real-ssh/streaming-$coordinator" --coordinate-at "$coordinator" \
        --performance-tuning workers=2 --no-progress --resource-limits bandwidth=8M --performance-tuning "$streaming" "$@"
    ssh destination sh -s -- "$coordinator" > /tmp/syq-real-ssh-streaming-check <<'EOF'
cat "/tmp/syq-real-ssh/streaming-$1"
EOF
    cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-streaming-check
done

printf 'case: batch overrides through a command-restricted receiver\n'
ssh source 'mkdir /tmp/syq-real-ssh/tuning-batches; for n in 1 2 3 4 5 6 7; do dd if=/dev/urandom of=/tmp/syq-real-ssh/tuning-batches/$n bs=1024 count=600 status=none; done'
syq cp --from source --srcs-in /tmp/syq-real-ssh/tuning-batches \
    --to destination --into /tmp/syq-real-ssh/tuning-batches --performance-tuning workers=1 --no-progress \
    --performance-tuning batch-files=3,batch-bytes=1M
assert_same_tree source /tmp/syq-real-ssh/tuning-batches \
    destination /tmp/syq-real-ssh/tuning-batches tuning-batches

printf 'case: grouped comparison through a command-restricted receiver\n'
ssh source sh -s <<'EOF'
set -eu
root=/tmp/syq-real-ssh/grouped-source
install -d "$root"
for n in 1 2 3 4 5 6 7 8; do
    head -c 262144 /dev/urandom >"$root/file-$n"
    # Byte 100 is changed below; make sure that changes the file.
    printf 0 | dd of="$root/file-$n" bs=1 seek=100 conv=notrunc status=none
done
EOF
syq cp --no-progress --from source --srcs-in /tmp/syq-real-ssh/grouped-source \
    --to destination --into /tmp/syq-real-ssh/grouped-destination
# Change one byte of half the files and the time of every file, so that each
# is compared: the receiver keeps the unchanged ones and patches the others,
# reusing all but the first 64 KiB block of each.
ssh source sh -s <<'EOF'
set -eu
root=/tmp/syq-real-ssh/grouped-source
for n in 1 2 3 4; do
    printf X | dd of="$root/file-$n" bs=1 seek=100 conv=notrunc status=none
done
touch -m -d @1700000000 "$root"/file-*
EOF
grouped_results=/tmp/syq-real-ssh-grouped.ndjson
grouped_debug=/tmp/syq-real-ssh-grouped.debug
if ! SYQ_DEBUG=1 syq cp --no-progress --results "$grouped_results" \
    --from source --srcs-in /tmp/syq-real-ssh/grouped-source \
    --to destination --into /tmp/syq-real-ssh/grouped-destination \
    2>"$grouped_debug"; then
    cat "$grouped_debug" >&2
    exit 1
fi
python3 - "$grouped_results" "$grouped_debug" <<'PYTHON'
import json, sys
from pathlib import Path
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert records[-1]['type'] == 'result' and records[-1]['status'] == 'success', records
assert records[-1]['bytes_transferred'] == 4 * 65536, records[-1]
# The receiver lists the files it patched; kept files are unchanged.
operations = {
    record['dst']['value'].rsplit('/', 1)[-1]: (record['action'], record['disposition'])
    for record in records
    if record['type'] == 'operation_result'
}
assert operations == {f'file-{n}': ('transfer_file', 'succeeded') for n in range(1, 5)}, operations
assert records[-1]['files_unchanged'] == 4, records[-1]
marker = 'syq: tuning observed: '
observed = [
    json.loads(line.split(marker, 1)[1])
    for line in Path(sys.argv[2]).read_text().splitlines()
    if marker in line
]
assert any(
    (counts.get('compared_files'), counts.get('kept_files'), counts.get('patched_files')) == (8, 4, 4)
    for counts in observed
), observed
PYTHON
assert_same_tree source /tmp/syq-real-ssh/grouped-source \
    destination /tmp/syq-real-ssh/grouped-destination grouped
# A file of which more differs than a group carries is streamed in pieces,
# each held to the receiver's grant: only the rewritten 20 MiB crosses.
ssh source sh -s <<'EOF'
set -eu
root=/tmp/syq-real-ssh/streamed-source
install -d "$root"
head -c 33554432 /dev/urandom >"$root/large"
EOF
syq cp --no-progress --from source --srcs-in /tmp/syq-real-ssh/streamed-source \
    --to destination --into /tmp/syq-real-ssh/streamed-destination
ssh source sh -s <<'EOF'
set -eu
root=/tmp/syq-real-ssh/streamed-source
head -c 20971520 /dev/urandom | dd of="$root/large" conv=notrunc status=none
touch -m -d @1700000000 "$root/large"
EOF
streamed_results=/tmp/syq-real-ssh-streamed.ndjson
streamed_debug=/tmp/syq-real-ssh-streamed.debug
if ! SYQ_DEBUG=1 syq cp --no-progress --results "$streamed_results" \
    --from source --srcs-in /tmp/syq-real-ssh/streamed-source \
    --to destination --into /tmp/syq-real-ssh/streamed-destination \
    2>"$streamed_debug"; then
    cat "$streamed_debug" >&2
    exit 1
fi
python3 - "$streamed_results" "$streamed_debug" <<'PYTHON'
import json, sys
from pathlib import Path
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert records[-1]['type'] == 'result' and records[-1]['status'] == 'success', records
assert records[-1]['bytes_transferred'] == 20 << 20, records[-1]
marker = 'syq: tuning observed: '
observed = [
    json.loads(line.split(marker, 1)[1])
    for line in Path(sys.argv[2]).read_text().splitlines()
    if marker in line
]
assert any(counts.get('streamed_patches') == 1 for counts in observed), observed
PYTHON
assert_same_tree source /tmp/syq-real-ssh/streamed-source \
    destination /tmp/syq-real-ssh/streamed-destination streamed

printf 'case: in-place copies of small files through a command-restricted receiver\n'
ssh source 'mkdir -p /tmp/syq-real-ssh/inplace-small; for n in 1 2 3; do printf "small $n" >/tmp/syq-real-ssh/inplace-small/$n; done'
syq cp --in-place=new --no-progress --from source --srcs-in /tmp/syq-real-ssh/inplace-small \
    --to destination --into /tmp/syq-real-ssh/inplace-small
ssh source 'printf "changed 2" >/tmp/syq-real-ssh/inplace-small/2'
syq cp --in-place=new --no-progress --from source --srcs-in /tmp/syq-real-ssh/inplace-small \
    --to destination --into /tmp/syq-real-ssh/inplace-small
assert_same_tree source /tmp/syq-real-ssh/inplace-small \
    destination /tmp/syq-real-ssh/inplace-small inplace-small

# Final checks after every selected case.
if ssh source 'pgrep -x syq >/dev/null' || ssh destination 'pgrep -x syq >/dev/null'; then
    echo 'a remote syq process survived the attached test suite' >&2
    exit 1
fi

printf 'real-SSH smoke suite passed\n'
