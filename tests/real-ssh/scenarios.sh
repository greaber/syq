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

# Every entry below a directory, with its type, mode and link target, and
# every file's digest, in a stable order.
manifest_script=$(cat <<'EOF'
set -eu
cd "$1"
{
    find . -mindepth 1 -printf '%y %m %p -> %l\n'
    find . -type f -exec sha256sum {} +
} | LC_ALL=C sort
EOF
)

remote_manifest() {
    printf '%s\n' "$manifest_script" | ssh "$1" sh -s -- "$2" >"$3"
}

local_manifest() {
    sh -c "$manifest_script" sh "$1"
}

# wait_until SECONDS DESCRIPTION COMMAND [ARGUMENT...]
# Runs COMMAND until it succeeds, which it must within SECONDS. What COMMAND
# prints is the state it observed: the wait reports the latest every five
# seconds, and fails with it at the deadline.
wait_until() {
    wait_deadline=$(($(date +%s) + $1))
    wait_progress=$(($(date +%s) + 5))
    wait_seconds=$1
    wait_description=$2
    shift 2
    while :; do
        if wait_state=$("$@" 2>&1); then
            return 0
        fi
        wait_now=$(date +%s)
        if [ "$wait_now" -ge "$wait_deadline" ]; then
            printf 'timed out after %ss waiting for %s; last state:\n%s\n' \
                "$wait_seconds" "$wait_description" "$wait_state" >&2
            return 1
        fi
        if [ "$wait_now" -ge "$wait_progress" ]; then
            printf 'waiting for %s; last state:\n%s\n' "$wait_description" "$wait_state" >&2
            wait_progress=$((wait_now + 5))
        fi
        sleep 0.2
    done
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

# file_digest HOST PATH: the file's SHA-256, where a HOST of - is this machine.
file_digest() {
    if [ "$1" = - ]; then
        sha256sum <"$2"
    else
        # shellcheck disable=SC2029
        ssh "$1" "sha256sum <$2"
    fi
}

# assert_small_copy RESULTS DEBUG COUNT SOURCE_HOST SOURCE DESTINATION_HOST DESTINATION
# A small copy run with SYQ_DEBUG=1 and --results settled successfully with
# one file in its result's COUNT, took the one-turn path, and left the
# destination with the source's bytes.
assert_small_copy() {
    small_status=$(tail -n 1 "$1")
    case "$small_status" in
        *'"status":"success"'*'"type":"result"'*) ;;
        *)
            echo 'small copy did not settle successfully:' >&2
            cat "$1" "$2" >&2
            return 1
            ;;
    esac
    case "$small_status" in
        *"\"$3\":1,"*|*"\"$3\":1}"*) ;;
        *) cat "$1" >&2; return 1 ;;
    esac
    if ! grep -q 'small copy: published' "$2"; then
        echo 'small copy did not use the one-turn path:' >&2
        cat "$2" >&2
        return 1
    fi
    test "$(file_digest "$4" "$5")" = "$(file_digest "$6" "$7")"
}

# exercise_tuning NAME WORKERS TUNING SECONDS
# With the tuning overrides TUNING and WORKERS workers at 8 MB/s, each copy
# ending within SECONDS: an upload and a download over TCP and over SSH, then
# a copy between servers coordinated by the source, the destination, and here.
exercise_tuning() {
    tuning_name=$1
    tuning_workers=$2
    tuning_overrides=$3
    tuning_seconds=$4
    for transport in tcp ssh; do
        if [ "$transport" = ssh ]; then set -- --no-tcp; else set --; fi
        timeout --kill-after=5s "$tuning_seconds" syq cp /tmp/syq-real-ssh-tuning.bin --to source \
            --as "/tmp/syq-real-ssh/$tuning_name-$transport" \
            --performance-tuning "workers=$tuning_workers" --no-progress \
            --resource-limits bandwidth=8M --performance-tuning "$tuning_overrides" "$@"
        timeout --kill-after=5s "$tuning_seconds" syq cp --from source "/tmp/syq-real-ssh/$tuning_name-$transport" \
            --as "/tmp/syq-real-ssh-$tuning_name-$transport-download" \
            --performance-tuning "workers=$tuning_workers" --no-progress \
            --resource-limits bandwidth=8M --performance-tuning "$tuning_overrides" "$@"
        cmp /tmp/syq-real-ssh-tuning.bin "/tmp/syq-real-ssh-$tuning_name-$transport-download"
    done
    for coordinator in src dst local; do
        case "$coordinator" in
            src) set -- ;;
            dst) set -- --peer-auth broker --no-tcp ;;
            local) set -- --no-tcp ;;
        esac
        timeout --kill-after=5s "$tuning_seconds" syq cp --from source "/tmp/syq-real-ssh/$tuning_name-tcp" \
            --to destination --as "/tmp/syq-real-ssh/$tuning_name-$coordinator" --coordinate-at "$coordinator" \
            --performance-tuning "workers=$tuning_workers" --no-progress --resource-limits bandwidth=8M \
            --performance-tuning "$tuning_overrides" "$@"
        # shellcheck disable=SC2029
        ssh destination cat "/tmp/syq-real-ssh/$tuning_name-$coordinator" > "/tmp/syq-real-ssh-$tuning_name-check"
        cmp /tmp/syq-real-ssh-tuning.bin "/tmp/syq-real-ssh-$tuning_name-check"
    done
}

assert_preview_counts() {
    python3 - "$1" "$2" "$3" <<'PYTHON'
import sys
from syq_real_ssh_lab import successful_results
records = successful_results(sys.argv[1])
result = records[-1]
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

# Remote filename completion through the helper of the completion cases.
completion_output=/tmp/syq-real-ssh-completion.out
completion_expected=/tmp/syq-real-ssh-completion.expected
complete_remote() {
    syq completion __complete fish 6 -- \
        syq cp --syq-path /tmp/syq-real-ssh/completion-helper --from source \
        /tmp/syq-real-ssh/completion/al >"$completion_output"
    cmp "$completion_expected" "$completion_output"
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

printf 'case: an enrollment that installs nothing leaves nothing pending\n'
# Refused by the server before it writes anything, here for a ~/.ssh it
# cannot write, or with no syq to install: nothing names the entry key, so
# no pending enrollment stays on this machine, and nothing on the server.
for refused_case in unwritable unavailable; do
    if [ "$refused_case" = unwritable ]; then
        ssh longhome@destination 'chmod 0500 ~/.ssh'
        refused_status=0
        syq receiver enroll longhome@destination \
            > /tmp/syq-refused-enrollment.log 2>&1 || refused_status=$?
        ssh longhome@destination 'chmod 0700 ~/.ssh'
        refused_expected='longhome@destination refused the enrollment: restricted copying needs a writable'
    else
        refused_status=0
        SYQ_TEST_MANAGEMENT_BUILD_UNAVAILABLE=1 syq receiver enroll longhome@destination \
            > /tmp/syq-refused-enrollment.log 2>&1 || refused_status=$?
        refused_expected='download the syq to install: unavailable (test)'
    fi
    refused_output=$(cat /tmp/syq-refused-enrollment.log)
    if [ "$refused_status" -eq 0 ]; then
        printf '%s: enrollment succeeded\n%s\n' "$refused_case" "$refused_output" >&2
        exit 1
    fi
    case "$refused_output" in
        *"remains pending"*)
            printf '%s: enrollment left pending\n%s\n' "$refused_case" "$refused_output" >&2
            exit 1 ;;
        *"$refused_expected"*) ;;
        *)
            printf '%s: unexpected enrollment failure\n%s\n' "$refused_case" "$refused_output" >&2
            exit 1 ;;
    esac
    case "$(syq receiver list)" in
        *longhome@destination*)
            printf '%s: enrollment listed\n' "$refused_case" >&2
            syq receiver list >&2
            exit 1 ;;
    esac
    ssh longhome@destination '! grep -s -q syq-enrollment: ~/.ssh/authorized_keys &&
        test -z "$(ls -A ~/.local/share/syq/enrollments 2>/dev/null)" &&
        ! ls -a ~/.local/lib/syq 2>/dev/null | grep -q "^.syq-stage"'
done

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
# Done once the old build's receiving is ready, or has exited.
upgrade_old_settled() {
    test -e /tmp/syq-upgrade-old-ready && return
    if kill -0 "$upgrade_old_pid" 2>/dev/null; then
        echo 'not ready'
        return 1
    fi
}
if ! wait_until 30 "the old build's receiving" upgrade_old_settled ||
    [ ! -e /tmp/syq-upgrade-old-ready ]; then
    cat /tmp/syq-upgrade-old.log >&2
    exit 1
fi
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
    # Status keeps answering while the service and provider switch.
    status = subprocess.run(
        ["syq", "persist", "receive", "status", "--json", "--pscope", scope],
        capture_output=True, text=True)
    if status.returncode:
        raise SystemExit(f"status failed during the switch: {status.stderr}")
    connections = json.loads(status.stdout)["connections"]
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

printf 'case: an SSH provider approves copies between two other servers\n'
python3 /usr/local/libexec/syq-test-provider-between-servers.py

printf 'case: storage authorization through the return connection\n'
python3 /usr/local/libexec/syq-test-storage-authorization.py

printf 'case: explicit automatic approval supports unattended copies\n'
syq persist receive on --auto-approve-root "$receive_root"
syq persist receive wait source --timeout 30
ssh source 'test -z "${SSH_AUTH_SOCK:-}"; SYQ_TEST_REQUIRE_TCP=1 syq cp --performance-tuning workers=2 --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/return-source --to @laptop --into first'
remote_manifest source /tmp/syq-real-ssh/return-source /tmp/syq-return-source.manifest
local_manifest "$receive_root/first" > /tmp/syq-return-local.manifest
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
# Earlier cases may add files to the source; every one of them was copied.
return_files=$(ssh source 'find /tmp/syq-real-ssh/return-source -type f | wc -l')
assert_preview_counts /tmp/syq-return-preview.ndjson 0 "$return_files"
ssh source 'syq cp --if-exists=keep /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as first/message.txt'

ssh source 'python3 /usr/local/libexec/syq-test-restricted-mapping.py named'

printf 'case: a restricted receiver on a network filesystem gets files while it creates directories\n'
# The laptop's receiving service, which serves the restricted receivers of
# the copies servers send it, counts its destination as a network filesystem
# (a debug-build hook). The server's copy then creates each batch's
# directories in small requests and sends a directory's files once it exists.
ssh source sh -s <<'NETWORK_TREE'
set -eu
root=/tmp/syq-real-ssh/network-tree
for directory in 0 1 2 3 4 5 6 7; do
    for sub in 0 1 2 3; do
        install -d -m 0750 "$root/d$directory/s$sub"
        for file in 0 1; do
            printf '%s\n' "d$directory/s$sub/f$file" >"$root/d$directory/s$sub/f$file"
        done
    done
done
NETWORK_TREE
syq persist off
# For the second copy below, the receiver also lacks a no-replace rename, and
# holds before it creates that copy's last directory.
SYQ_TEST_NETWORK_FILESYSTEM=1 \
    SYQ_TEST_NO_RENAME_NOREPLACE=1 \
    SYQ_TEST_DESTINATION_MUTATION_SUFFIX=network-keep/d7/s3 \
    SYQ_TEST_DESTINATION_MUTATION_READY_FILE=/tmp/syq-network-held \
    SYQ_TEST_DESTINATION_MUTATION_CONTINUE_FILE=/tmp/syq-network-continue \
    syq persist connect source
syq persist receive wait source --timeout 30
ssh source 'syq persist destinations wait laptop --timeout 30'
ssh source 'SYQ_TUNING_HISTORY=/tmp/syq-network-tree.sqlite syq cp --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/network-tree --to @laptop --into network-tree'
# The copy took its destination for a network filesystem, which is what has it
# create directories this way.
ssh source python3 - <<'NETWORK_SEEN'
import json
import sqlite3
rows = sqlite3.connect("/tmp/syq-network-tree.sqlite").execute(
    "SELECT data FROM events WHERE json_extract(data, '$.kind') = 'starting_count'").fetchall()
assert rows and all(json.loads(row[0])["data"]["network_destination"] for row in rows), rows
NETWORK_SEEN
remote_manifest source /tmp/syq-real-ssh/network-tree /tmp/syq-network-tree-source.manifest
local_manifest "$receive_root/network-tree" > /tmp/syq-network-tree-local.manifest
diff -u /tmp/syq-network-tree-source.manifest /tmp/syq-network-tree-local.manifest
# A copy that keeps existing files, into a directory that holds one, on a
# filesystem without a no-replace rename: the receiver records the
# directories it creates, so that a file published below one needs no second
# lookup. While it holds before creating the last directory, a file below a
# directory it created earlier has already been published.
mkdir -p "$receive_root/network-keep/d0"
printf 'kept\n' >"$receive_root/network-keep/d0/existing"
rm -f /tmp/syq-network-held /tmp/syq-network-continue
ssh source 'syq cp --if-exists=keep --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/network-tree --to @laptop --into network-keep' &
keep_copy=$!
network_keep_held() {
    test -e /tmp/syq-network-held && test -e "$receive_root/network-keep/d0/s0/f0" && return
    printf 'held: %s; published below a created directory: %s\n' \
        "$(test -e /tmp/syq-network-held && echo yes || echo no)" \
        "$(test -e "$receive_root/network-keep/d0/s0/f0" && echo yes || echo no)"
    return 1
}
if ! wait_until 30 'the receiver to hold with a file published' network_keep_held; then
    touch /tmp/syq-network-continue
    exit 1
fi
test ! -e "$receive_root/network-keep/d7/s3"
touch /tmp/syq-network-continue
wait "$keep_copy"
test "$(cat "$receive_root/network-keep/d0/existing")" = kept
rm "$receive_root/network-keep/d0/existing"
local_manifest "$receive_root/network-keep" > /tmp/syq-network-keep-local.manifest
# The directory that held the existing file keeps its own mode.
grep -v '^d [0-7]* ./d0 -> $' /tmp/syq-network-tree-source.manifest >/tmp/syq-network-keep-source.manifest
grep -v '^d [0-7]* ./d0 -> $' /tmp/syq-network-keep-local.manifest | diff -u /tmp/syq-network-keep-source.manifest -
# A mapping there puts every file four new directories deep. The receiver
# creates those parents only where nothing is, all of a request's such
# creations at once, so a parent and its child never go in one request.
ssh source python3 - <<'NETWORK_MAPPING'
import json
with open("/tmp/syq-network-mapping.ndjson", "w") as manifest:
    for d in range(8):
        for s in range(4):
            for f in range(2):
                source = f"d{d}/s{s}/f{f}"
                manifest.write(json.dumps({
                    "src": {"encoding": "utf-8", "value": source},
                    "dst": {"encoding": "utf-8", "value": f"nested/d{d}/s{s}/deep/f{f}"},
                }) + "\n")
NETWORK_MAPPING
ssh source 'syq cp -C /tmp/syq-real-ssh/network-tree --mapping /tmp/syq-network-mapping.ndjson --to @laptop --into network-mapping'
for d in 0 1 2 3 4 5 6 7; do
    for s in 0 1 2 3; do
        for f in 0 1; do
            test "$(cat "$receive_root/network-mapping/nested/d$d/s$s/deep/f$f")" = "d$d/s$s/f$f"
        done
    done
done
# Keeping what exists, the receiver looks up each directory before creating
# it, which fails while its new parent is in the same request: three levels
# of new directories go one level at a time.
ssh source sh -s <<'NETWORK_DEEP'
set -eu
root=/tmp/syq-real-ssh/network-deep
for d in 0 1 2 3 4 5 6 7; do
    for s in 0 1 2 3; do
        install -d -m 0750 "$root/d$d/s$s/deep"
        printf '%s\n' "d$d/s$s" >"$root/d$d/s$s/deep/f"
    done
done
NETWORK_DEEP
ssh source 'syq cp --if-exists=keep --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/network-deep --to @laptop --into network-deep-keep'
remote_manifest source /tmp/syq-real-ssh/network-deep /tmp/syq-network-deep-source.manifest
local_manifest "$receive_root/network-deep-keep" | diff -u /tmp/syq-network-deep-source.manifest -
syq persist off
syq persist connect source
syq persist receive wait source --timeout 30
ssh source 'syq persist destinations wait laptop --timeout 30'
# The same two copies onto the receive root's own disk, where a batch's new
# directories go in as few requests as the receiver allows.
ssh source 'syq cp -C /tmp/syq-real-ssh/network-tree --mapping /tmp/syq-network-mapping.ndjson --to @laptop --into local-mapping'
for d in 0 1 2 3 4 5 6 7; do
    for s in 0 1 2 3; do
        for f in 0 1; do
            test "$(cat "$receive_root/local-mapping/nested/d$d/s$s/deep/f$f")" = "d$d/s$s/f$f"
        done
    done
done
ssh source 'syq cp --if-exists=keep --copy-metadata permissions --srcs-in /tmp/syq-real-ssh/network-deep --to @laptop --into local-deep-keep'
local_manifest "$receive_root/local-deep-keep" | diff -u /tmp/syq-network-deep-source.manifest -

printf 'case: a restricted receiver answers lookups sent ahead of their scan batches\n'
# A copy plans its source in batches and asks the destination about several
# of them ahead of their turn. When an earlier batch changes the destination
# it drops those replies and asks again. The laptop's receiver, keeping
# existing files on a filesystem without a no-replace rename (a debug-build
# hook), publishes by what it recorded of those lookups: every new file's
# name must have been found absent, so that it is renamed into place.
ssh source python3 - <<'AHEAD_TREE'
import os
root = "/tmp/syq-real-ssh/ahead-tree/a"
os.makedirs(root)
for index in range(12000):
    with open(f"{root}/f{index:05}", "w") as out:
        out.write("data")
AHEAD_TREE
syq persist off
SYQ_TEST_NO_RENAME_NOREPLACE=1 SYQ_TEST_PUBLICATION_CLAIMS=/tmp/syq-ahead-claims \
    syq persist connect source
syq persist receive wait source --timeout 30
ssh source 'syq persist destinations wait laptop --timeout 30'
ahead_copy() {
    ssh source 'rm -f /tmp/syq-ahead-early'
    rm -f /tmp/syq-ahead-claims
    # The scan holds every batch it may, so each lookup that can go early does.
    # $1: more options, quoted for the source's shell.
    # shellcheck disable=SC2029
    ssh source "SYQ_TEST_SCAN_AHEAD_WAIT=1 SYQ_TEST_EARLY_LOOKUPS=/tmp/syq-ahead-early syq cp --if-exists=keep --no-progress --srcs-in /tmp/syq-real-ssh/ahead-tree --to @laptop --into ahead ${1-}"
    # What became of each early lookup, and what the receiver's record gave
    # each publication.
    # A copy into an empty destination asks about no batch.
    ssh source 'test ! -e /tmp/syq-ahead-early || cut -d" " -f1 /tmp/syq-ahead-early | sort | uniq -c' >/tmp/syq-ahead-fates
    { test ! -e /tmp/syq-ahead-claims || sort /tmp/syq-ahead-claims | uniq -c; } >/tmp/syq-ahead-claimed
}
ahead_count() {
    awk -v name="$2" '$2 == name { count = $1 } END { print count + 0 }' "$1"
}
ahead_copy
test "$(find "$receive_root/ahead/a" -type f | wc -l)" -eq 12000
# The destination now holds the tree. A new directory sorts after the
# existing files, two batches into the scan, so the batch that holds it
# creates it while the lookups for the batches after it are in flight; those
# batches hold new files of the existing directory, and the new directory's
# own files follow.
ssh source python3 - <<'AHEAD_MORE'
import os
root = "/tmp/syq-real-ssh/ahead-tree/a"
os.mkdir(f"{root}/fz.d")
for index in range(4000):
    with open(f"{root}/fz.d/h{index:05}", "w") as out:
        out.write("data")
    with open(f"{root}/g{index:05}", "w") as out:
        out.write("data")
AHEAD_MORE
printf 'kept\n' >"$receive_root/ahead/a/f00007"
ahead_copy
ahead_sent=$(ahead_count /tmp/syq-ahead-fates sent)
ahead_used=$(ahead_count /tmp/syq-ahead-fates used)
ahead_dropped=$(($(ahead_count /tmp/syq-ahead-fates repeated) + $(ahead_count /tmp/syq-ahead-fates withdrawn)))
ahead_discarded=$(ahead_count /tmp/syq-ahead-fates discarded)
if [ "$ahead_used" -lt 1 ] || [ "$ahead_dropped" -lt 1 ] ||
    [ "$ahead_sent" -ne $((ahead_used + ahead_dropped + ahead_discarded)) ]; then
    echo 'the copy did not both use and drop lookups sent ahead:' >&2
    cat /tmp/syq-ahead-fates >&2
    exit 1
fi
# Every new file was published at a name the receiver had recorded absent,
# its own or beneath the directory it created: none at a name it did not
# know, which it would have had to link into place.
if [ "$(ahead_count /tmp/syq-ahead-claimed Absent)" -ne 8000 ] ||
    [ "$(wc -l </tmp/syq-ahead-claimed)" -ne 1 ]; then
    echo 'the receiver did not find every new name absent:' >&2
    cat /tmp/syq-ahead-claimed >&2
    exit 1
fi
test "$(cat "$receive_root/ahead/a/f00007")" = kept
printf 'data' >"$receive_root/ahead/a/f00007"
remote_manifest source /tmp/syq-real-ssh/ahead-tree /tmp/syq-ahead-source.manifest
local_manifest "$receive_root/ahead" | diff -u /tmp/syq-ahead-source.manifest -
# Unchanged, every lookup sent ahead is used and nothing is published.
ahead_copy
ahead_sent=$(ahead_count /tmp/syq-ahead-fates sent)
if [ "$ahead_sent" -lt 2 ] || [ "$ahead_sent" -ne "$(ahead_count /tmp/syq-ahead-fates used)" ] ||
    [ -s /tmp/syq-ahead-claimed ]; then
    echo 'an unchanged copy did not use every lookup it sent ahead:' >&2
    cat /tmp/syq-ahead-fates /tmp/syq-ahead-claimed >&2
    exit 1
fi
# The same with --where selecting a tenth of the files: the lookups sent
# ahead name the selected entries, so each is used.
ahead_copy "--where 'src.name glob \"*5\"'"
ahead_sent=$(ahead_count /tmp/syq-ahead-fates sent)
if [ "$ahead_sent" -lt 2 ] || [ "$ahead_sent" -ne "$(ahead_count /tmp/syq-ahead-fates used)" ] ||
    [ -s /tmp/syq-ahead-claimed ]; then
    echo 'an unchanged copy with --where did not use every lookup it sent ahead:' >&2
    cat /tmp/syq-ahead-fates /tmp/syq-ahead-claimed >&2
    exit 1
fi
syq persist off
syq persist connect source
syq persist receive wait source --timeout 30
ssh source 'syq persist destinations wait laptop --timeout 30'
printf 'case: a restricted receiver gets the final metadata of 4,300 directories in requests sent together\n'
# The directories' final metadata takes two requests, and the server sends
# the second before the first is answered: this debug build records each
# request's directories and the requests still unanswered when it went. The
# laptop's restricted receiver authorizes and runs them in turn, and every
# directory gets its source's time.
ssh source sh -s <<'MANY_DIRECTORIES'
set -eu
root=/tmp/syq-real-ssh/many-directories
requests=/tmp/syq-many-directories.requests
rm -rf "$root" "$requests"
mkdir -p "$root"
directory=0
while [ "$directory" -lt 4300 ]; do
    mkdir "$root/d$directory"
    directory=$((directory + 1))
done
find "$root" -mindepth 1 -type d -exec touch -d @981173106 {} +
SYQ_TEST_DIRECTORY_METADATA_REQUESTS=$requests \
    syq cp --no-progress --srcs-in "$root" --to @laptop --into many-directories
if [ "$(wc -l <"$requests")" -ne 2 ] || [ "$(head -n 1 "$requests")" != '4096 0' ] ||
    [ "$(tail -n 1 "$requests" | cut -d ' ' -f 2)" != 1 ]; then
    echo 'the final directory metadata did not go in two requests sent together:' >&2
    cat "$requests" >&2
    exit 1
fi
MANY_DIRECTORIES
test "$(find "$receive_root/many-directories" -mindepth 1 -type d | wc -l)" -eq 4300
many_times=$(find "$receive_root/many-directories" -mindepth 1 -type d -printf '%Ts\n' | sort -u)
if [ "$many_times" != 981173106 ]; then
    printf 'copied directories lack their source time; the times found:\n%s\n' "$many_times" >&2
    exit 1
fi

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
named_partial_ready() {
    partial_count=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-tmp.*' | wc -l)
    if [ "$partial_count" -eq 1 ]; then
        partial=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-tmp.*')
        partial_prefix=$(dd if="$partial" bs=1M count=4 status=none | sha256sum)
        if [ "$partial_prefix" = "$source_prefix" ]; then return; fi
    fi
    echo "partial_count=$partial_count"
    return 1
}
wait_until 25 'the named copy partial' named_partial_ready
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
{
    printf '%s\000' '/tmp/syq-real-ssh/completion/alpha file'
    printf '%s\000' '/tmp/syq-real-ssh/completion/alpine/'
} >"$completion_expected"
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
# Done once a login has ended; the count must then be exactly one.
completion_login_ended() {
    logins=$(direct_logins)
    echo "direct_logins=$logins"
    [ "$logins" -ge 1 ]
}
if ! wait_until 5 'the first completion login to end' completion_login_ended ||
    [ "$(direct_logins)" -ne 1 ]; then
    echo "first completion login count: expected 1, observed $(direct_logins)" >&2
    cat "$trace" >&2
    exit 1
fi
session_pool_ready() {
    spares=$(open_spares)
    echo "open_spares=$spares"
    [ "$spares" -ge 1 ]
}
if ! wait_until 15 'the session pool' session_pool_ready; then
    cat "$trace" >&2
    exit 1
fi
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
assert_small_copy "$small_results" "$small_debug" files_transferred \
    - "$small_source" source /tmp/syq-real-ssh/small-destination/syq-real-ssh-small.bin

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
    small_count=files_transferred
    if [ "$small_case" = unchanged ]; then
        small_count=files_unchanged
    fi
    assert_small_copy "$small_results" "$small_debug" "$small_count" \
        - "$small_source" source /tmp/syq-real-ssh/small-destination/syq-real-ssh-small.bin
    if grep -q 'TCP route probes started' "$small_debug" ||
        ! grep -q 'OpenSSH_' "$small_debug"; then
        cat "$small_debug" >&2
        exit 1
    fi
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
    small_count=files_transferred
    if [ "$small_case" = unchanged ]; then
        small_count=files_unchanged
    fi
    assert_small_copy "$small_results" "$small_debug" "$small_count" \
        source "$restricted_small_source" destination "$restricted_small/restricted-small.bin"
    if ! grep -q 'syq-receiver\|restricted' "$small_debug"; then
        echo 'small copy to a restricted destination did not use the one-turn path:' >&2
        cat "$small_debug" >&2
        exit 1
    fi
done

printf 'case: a capped small copy to a restricted destination takes one turn within the cap\n'
# The sender paces the one-turn payload: 256 KiB at 320 KiB/s takes 0.8 s.
# The shortcut takes payloads of up to a second at the cap.
restricted_capped=/tmp/syq-real-ssh/restricted-small-capped.bin
small_results=/tmp/syq-real-ssh-restricted-small-capped.ndjson
# shellcheck disable=SC2029
ssh source "head -c 262144 /dev/urandom >$restricted_capped"
if ! SYQ_DEBUG=1 syq cp --no-progress --no-compress --resource-limits bandwidth=320K \
    --results "$small_results" --from source "$restricted_capped" \
    --to destination --into "$restricted_small" 2>"$small_debug"; then
    cat "$small_debug" >&2
    exit 1
fi
assert_small_copy "$small_results" "$small_debug" files_transferred \
    source "$restricted_capped" destination "$restricted_small/restricted-small-capped.bin"
if ! tail -n 1 "$small_results" | python3 -c '
import json, sys
sys.exit(json.load(sys.stdin)["timings"]["transfer_ms"] < 700)
'; then
    echo 'capped small copy to a restricted destination skipped the cap:' >&2
    cat "$small_results" "$small_debug" >&2
    exit 1
fi

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
import sys
from syq_real_ssh_lab import successful_results
result = successful_results(sys.argv[1])[-1]
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

printf 'case: a copy refused by a receiver of another build updates it on the next copy\n'
# The laptop's record says the destination's receiver runs this build, as
# after restoring the laptop's state from a backup, but the lab's second
# build has updated the receiver since. The receiver refuses the copy for
# its build; syq says so and marks its record out of date, so the next
# copy updates the receiver to this build first.
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
# Let the second build update the receiver behind this build's record.
stale_receiver() {
    cp "$rebuild_record/enrollment.json" /tmp/syq-real-ssh-rebuild-enrollment.json
    syq-other-build receiver enroll destination >/dev/null
    test "$(syq-other-build receiver list | awk -F '\t' '$3 == "syq@destination" { print $4 }')" = \
        "$(syq-other-build --build-identity)"
    cp /tmp/syq-real-ssh-rebuild-enrollment.json "$rebuild_record/enrollment.json"
}
stale_receiver
ssh destination 'rm -rf /tmp/syq-real-ssh/rebuild-destination'
rebuild_copy() {
    syq cp --no-progress "$@" \
        --from source --srcs-in /tmp/syq-real-ssh/rebuild-source \
        --to destination --into /tmp/syq-real-ssh/rebuild-destination 2>&1
}
# Its results stream counts every error record it holds: the receiver's
# refusal, relayed as it arrived, and the failure here.
rebuild_refused_results() {
    python3 - "$1" <<'PYTHON'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1])]
counted = [r for r in records if r["type"] == "error" and "diagnostic_for" not in r]
assert records[-1]["type"] == "result" and records[-1]["status"] == "failed", records
# At least the relayed refusal and this machine's own failure.
assert len(counted) >= 2 and records[-1]["errors"] == len(counted), records
PYTHON
}
# The refused copy says to run it again, and changes nothing there.
rm -f /tmp/syq-real-ssh-rebuild-refused.ndjson
if rebuild_output=$(rebuild_copy --results /tmp/syq-real-ssh-rebuild-refused.ndjson); then
    printf '%s\n' "$rebuild_output" >&2
    echo 'a copy against a receiver of another build unexpectedly succeeded' >&2
    exit 1
fi
case "$rebuild_output" in
    *'the restricted receiver on '*'runs another syq build; run the copy again, which updates it first'*) ;;
    *) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
esac
ssh destination 'test ! -e /tmp/syq-real-ssh/rebuild-destination'
rebuild_refused_results /tmp/syq-real-ssh-rebuild-refused.ndjson
# The next copy updates the receiver and runs.
rm -f /tmp/syq-real-ssh-rebuild.ndjson
rebuild_output=$(rebuild_copy --results /tmp/syq-real-ssh-rebuild.ndjson) || {
    printf '%s\n' "$rebuild_output" >&2
    exit 1
}
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
# A dry run says so and updates nothing, and the next copy updates it.
stale_receiver
ssh destination 'rm -rf /tmp/syq-real-ssh/rebuild-destination'
rm -f /tmp/syq-real-ssh-rebuild-refused.ndjson
if rebuild_output=$(rebuild_copy --dry-run --results /tmp/syq-real-ssh-rebuild-refused.ndjson); then
    printf '%s\n' "$rebuild_output" >&2
    echo 'a dry run against a receiver of another build unexpectedly succeeded' >&2
    exit 1
fi
case "$rebuild_output" in
    *'a dry run does not update it, but the next copy does'*) ;;
    *) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
esac
rebuild_refused_results /tmp/syq-real-ssh-rebuild-refused.ndjson
rebuild_output=$(rebuild_copy) || {
    printf '%s\n' "$rebuild_output" >&2
    exit 1
}
assert_same_tree source /tmp/syq-real-ssh/rebuild-source \
    destination /tmp/syq-real-ssh/rebuild-destination rebuild-after-dry-run
# A detached copy is refused the same way, before it detaches.
stale_receiver
ssh destination 'rm -rf /tmp/syq-real-ssh/rebuild-detached'
rebuild_detached() {
    syq cp --no-progress --detach \
        --from source --srcs-in /tmp/syq-real-ssh/rebuild-source \
        --to destination --into /tmp/syq-real-ssh/rebuild-detached 2>&1
}
if rebuild_output=$(rebuild_detached); then
    printf '%s\n' "$rebuild_output" >&2
    echo 'a detached copy against a receiver of another build unexpectedly started' >&2
    exit 1
fi
case "$rebuild_output" in
    *'syq: started on '*) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
    *'runs another syq build; run the copy again, which updates it first'*) ;;
    *) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
esac
rebuild_output=$(rebuild_detached) || {
    printf '%s\n' "$rebuild_output" >&2
    exit 1
}
case "$rebuild_output" in
    *'syq: started on '*) ;;
    *) printf '%s\n' "$rebuild_output" >&2; exit 1 ;;
esac
rebuild_deadline=$(($(date +%s) + 60))
until assert_same_tree source /tmp/syq-real-ssh/rebuild-source \
    destination /tmp/syq-real-ssh/rebuild-detached rebuild-detached >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$rebuild_deadline" ]; then
        assert_same_tree source /tmp/syq-real-ssh/rebuild-source \
            destination /tmp/syq-real-ssh/rebuild-detached rebuild-detached
        echo 'the detached copy did not finish within 60 seconds' >&2
        exit 1
    fi
    echo 'waiting for the detached copy after its receiver was updated'
    sleep 2
done

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
killed_partials_are() {
    listing=$(killed_partials)
    printf '%s\n' "$listing"
    [ "$(printf '%s' "$listing" | grep -c .)" -eq "$1" ]
}
syq cp --no-progress --resource-limits bandwidth=32 \
    --performance-tuning workers=2,copy-path=ranges \
    --from source --srcs-in /tmp/syq-real-ssh/killed-source \
    --to destination --into "$killed_root" &
killed_copy_pid=$!
wait_until 30 '2 partials' killed_partials_are 2
ssh source 'pkill -KILL -n -x syq'
if wait "$killed_copy_pid"; then
    echo 'a copy whose coordinator was killed reported success' >&2
    exit 1
fi
wait_until 30 '1 partial' killed_partials_are 1
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
import sys
from syq_real_ssh_lab import successful_results, tuning_observed
records = successful_results(sys.argv[1])
assert records[-1]['errors'] == 0, records[-1]
if sys.argv[3] != 'whole':
    assert records[-1]['bytes_transferred'] == 4 * 65536, records[-1]
    observed = tuning_observed(sys.argv[2])
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

printf 'case: a keep grant fails only the changes inside directories it may not widen\n'
# Two read-only directories at the destination, one holding a file; the
# source has that file, a new one in each, and more beside them.
# --if-exists=keep lets a restricted receiver change no existing directory's
# permissions, so --widen-dirs widens neither, under rsync or all: the new
# files in them fail by name, everything else is copied, and the copy says
# why once. An ordinary receiver that may not widen leaves the same tree and
# status.
keep_tree=$(cat <<'PY_KEEP_TREE'
import os, sys
root = sys.argv[1]
for name in ['sub/old', 'sub/new', 'second/new', 'fresh/file', 'beside']:
    os.makedirs(os.path.dirname(f'{root}/{name}'), exist_ok=True)
    with open(f'{root}/{name}', 'w') as f:
        f.write(name)
PY_KEEP_TREE
)
printf '%s\n' "$keep_tree" | python3 - /tmp/syq-real-ssh-keep-tree
printf '%s\n' "$keep_tree" | ssh source python3 - /tmp/syq-real-ssh/keep-tree
for keep_receiver in ordinary rsync all; do
    keep_destination=/tmp/syq-real-ssh/keep-$keep_receiver
    keep_errors=/tmp/syq-real-ssh-keep-$keep_receiver.err
    # The fixture path is set by this loop.
    # shellcheck disable=SC2029
    ssh destination "mkdir -p $keep_destination/sub $keep_destination/second && printf existing > $keep_destination/sub/old && chmod 555 $keep_destination/sub $keep_destination/second"
    keep_status=0
    if [ "$keep_receiver" = ordinary ]; then
        syq cp --no-progress --if-exists=keep --widen-dirs=none \
            --srcs-in /tmp/syq-real-ssh-keep-tree --to destination --into "$keep_destination" \
            2>"$keep_errors" || keep_status=$?
    else
        syq cp --no-progress --if-exists=keep --widen-dirs="$keep_receiver" \
            --from source --srcs-in /tmp/syq-real-ssh/keep-tree \
            --to destination --into "$keep_destination" \
            2>"$keep_errors" || keep_status=$?
    fi
    cat "$keep_errors" >&2
    test "$keep_status" = 23
    grep -F 'syq: sub/new: ' "$keep_errors" >/dev/null
    grep -F 'syq: second/new: ' "$keep_errors" >/dev/null
    if [ "$keep_receiver" != ordinary ]; then
        test "$(grep -c -F -e "--if-exists=keep lets the restricted receiver change no existing directory's permissions" "$keep_errors")" = 1
        grep -F 'it is not widened either' "$keep_errors" >/dev/null
        if grep -F -e refused -e contradicts "$keep_errors" >&2; then
            echo 'the restricted receiver refused a request of the keep copy' >&2
            exit 1
        fi
    fi
    remote_manifest destination "$keep_destination" "/tmp/syq-real-ssh-keep-$keep_receiver.manifest"
done
cmp /tmp/syq-real-ssh-keep-ordinary.manifest /tmp/syq-real-ssh-keep-rsync.manifest
cmp /tmp/syq-real-ssh-keep-ordinary.manifest /tmp/syq-real-ssh-keep-all.manifest
ssh destination 'cd /tmp/syq-real-ssh/keep-rsync && test "$(cat sub/old)" = existing && test ! -e sub/new && test ! -e second/new && test "$(cat beside)" = beside && test "$(cat fresh/file)" = fresh/file && test "$(stat -c %a sub second | tr "\n" " ")" = "555 555 "'

# Pruning under the same grant: destination-only files in read-only
# directories fail to be removed, by name, and one beside them is removed.
ssh destination 'mkdir -p /tmp/syq-real-ssh/keep-prune/gone /tmp/syq-real-ssh/keep-prune/gone-too && cd /tmp/syq-real-ssh/keep-prune && touch gone/extra gone-too/extra stale && chmod 555 gone gone-too'
keep_status=0
syq cp --no-progress --if-exists=keep --widen-dirs=all --prune \
    --from source --srcs-in /tmp/syq-real-ssh/keep-tree \
    --to destination --into /tmp/syq-real-ssh/keep-prune \
    2>/tmp/syq-real-ssh-keep-prune.err || keep_status=$?
cat /tmp/syq-real-ssh-keep-prune.err >&2
test "$keep_status" = 23
grep -F 'syq: delete gone/extra: ' /tmp/syq-real-ssh-keep-prune.err >/dev/null
grep -F 'syq: delete gone-too/extra: ' /tmp/syq-real-ssh-keep-prune.err >/dev/null
# A preview names the directories it cannot look inside.
ssh destination 'mkdir -p /tmp/syq-real-ssh/keep-preview/sub /tmp/syq-real-ssh/keep-preview/second && chmod 600 /tmp/syq-real-ssh/keep-preview/sub /tmp/syq-real-ssh/keep-preview/second'
keep_status=0
syq cp --no-progress --if-exists=keep --widen-dirs=rsync --dry-run \
    --from source --srcs-in /tmp/syq-real-ssh/keep-tree \
    --to destination --into /tmp/syq-real-ssh/keep-preview \
    >/dev/null 2>/tmp/syq-real-ssh-keep-preview.err || keep_status=$?
cat /tmp/syq-real-ssh-keep-preview.err >&2
test "$keep_status" = 23
test "$(grep -c -F 'not inspected: you own this directory, but it lacks owner search permission' /tmp/syq-real-ssh-keep-preview.err)" = 2
# Either way the copy says why once, and the receiver refuses nothing.
for keep_errors in /tmp/syq-real-ssh-keep-prune.err /tmp/syq-real-ssh-keep-preview.err; do
    test "$(grep -c -F -e "--if-exists=keep lets the restricted receiver change no existing directory's permissions" "$keep_errors")" = 1
    grep -F 'it is not widened either' "$keep_errors" >/dev/null
    if grep -F -e refused -e contradicts "$keep_errors" >&2; then
        echo 'the restricted receiver refused a request of the keep copy' >&2
        exit 1
    fi
done
ssh destination 'cd /tmp/syq-real-ssh/keep-prune && test ! -e stale && test -e gone/extra && test -e gone-too/extra && test "$(cat sub/new)" = sub/new && test "$(stat -c %a gone gone-too | tr "\n" " ")" = "555 555 " && chmod 755 gone gone-too /tmp/syq-real-ssh/keep-preview/sub /tmp/syq-real-ssh/keep-preview/second'

# An existing --as directory the copy cannot search is refused up front with
# the same reason, not with the suggestion to widen more.
ssh destination 'mkdir /tmp/syq-real-ssh/keep-as && chmod 600 /tmp/syq-real-ssh/keep-as'
keep_status=0
syq cp --no-progress --if-exists=keep --widen-dirs=rsync \
    --from source /tmp/syq-real-ssh/keep-tree \
    --to destination --as /tmp/syq-real-ssh/keep-as \
    2>/tmp/syq-real-ssh-keep-as.err || keep_status=$?
cat /tmp/syq-real-ssh-keep-as.err >&2
test "$keep_status" = 1
grep -F 'search destination directory' /tmp/syq-real-ssh-keep-as.err |
    grep -F -e "--if-exists=keep lets the restricted receiver change no existing directory's permissions" >/dev/null
if grep -F 'may help' /tmp/syq-real-ssh-keep-as.err >&2; then
    echo 'a keep copy suggested a widening mode that cannot help' >&2
    exit 1
fi
ssh destination 'test "$(stat -c %a /tmp/syq-real-ssh/keep-as)" = 600 && chmod 755 /tmp/syq-real-ssh/keep-as'

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
dd if=/dev/urandom of=/tmp/syq-real-ssh-tuning.bin bs=1M count=9 status=none
exercise_tuning tuning 1 copy-path=ranges,request-size=2M,pipeline-depth=64,split-min-size=8M 120s

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
exercise_tuning streaming 2 copy-path=streaming,request-size=128K,split-min-size=1M 25s

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
import sys
from syq_real_ssh_lab import successful_results, tuning_observed
records = successful_results(sys.argv[1])
assert records[-1]['bytes_transferred'] == 4 * 65536, records[-1]
# The receiver lists the files it patched; kept files are unchanged.
operations = {
    record['dst']['value'].rsplit('/', 1)[-1]: (record['action'], record['disposition'])
    for record in records
    if record['type'] == 'operation_result'
}
assert operations == {f'file-{n}': ('transfer_file', 'succeeded') for n in range(1, 5)}, operations
assert records[-1]['files_unchanged'] == 4, records[-1]
observed = tuning_observed(sys.argv[2])
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
import sys
from syq_real_ssh_lab import successful_results, tuning_observed
records = successful_results(sys.argv[1])
assert records[-1]['bytes_transferred'] == 20 << 20, records[-1]
observed = tuning_observed(sys.argv[2])
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
