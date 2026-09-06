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
    remote_manifest "$source_host" "$source_root" "$source_manifest"
    remote_manifest "$destination_host" "$destination_root" "$destination_manifest"
    diff -u "$source_manifest" "$destination_manifest"
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

printf 'case: source build uploads itself over real SSH to empty helper caches\n'
printf 'development helper upload\n' > /tmp/dev-helper-upload.txt
for host in source destination; do
    ssh "$host" 'test ! -e "$HOME/.cache/syq/helpers"'
    syq cp /tmp/dev-helper-upload.txt --to "$host" --into /tmp
    ssh "$host" 'cmp /tmp/dev-helper-upload.txt /dev/stdin' < /tmp/dev-helper-upload.txt
done
# The completion scenario expects to discover only its own endpoint.
syq completion cache clear >/dev/null

printf 'case: named return destination works from independent server shells without agent forwarding\n'
receive_root=/tmp/syq-real-ssh-receive
mkdir -p "$receive_root" /tmp/syq-real-ssh-receive-other
make_tree source /tmp/syq-real-ssh/return-source return
syq persist on
# The ordinary copy ends before receiving readiness: no foreground receiver.
syq cp --from source --srcs-in /tmp/syq-real-ssh/return-source --into /tmp/syq-return-pull
syq recv wait source --timeout 30
# The container hostname is the laptop's default advertised name.
# shellcheck disable=SC2029
ssh source "syq destination wait $(hostname) --timeout 5"
syq recv on --name laptop --root "$receive_root"
syq recv wait source --timeout 30
ssh source 'syq destination wait laptop --timeout 30'
printf 'case: return copies await local approval and denial leaves no destination\n'
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as denied' &
return_copy_pid=$!
syq recv pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; r=json.load(open("/tmp/syq-pending.json")); assert len(r)==1 and "source" in r[0]["from"] and "denied" in r[0]["destination"],r; print(r[0]["id"])')
test ! -e "$receive_root/denied"
syq recv deny "$request_id"
if wait "$return_copy_pid"; then echo 'denied copy succeeded' >&2; exit 1; else test "$?" -ne 124; fi
return_copy_pid=
test ! -e "$receive_root/denied"
if syq recv approve "$request_id"; then echo 'denied approval ID was reused' >&2; exit 1; fi

printf 'case: approval allows only the pending copy once\n'
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as approved' &
return_copy_pid=$!
syq recv pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
test ! -e "$receive_root/approved"
syq recv approve "$request_id"
wait "$return_copy_pid"
return_copy_pid=
printf 'return\n' | cmp - "$receive_root/approved"
if syq recv approve "$request_id"; then echo 'used approval ID was reused' >&2; exit 1; fi

printf 'case: disconnected requests cannot be approved later\n'
ssh source 'timeout 2 syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as disconnected' &
return_copy_pid=$!
syq recv pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
if wait "$return_copy_pid"; then echo 'unapproved copy succeeded' >&2; exit 1; fi
return_copy_pid=
python3 - <<'PYWAIT'
import json, subprocess, time
deadline = time.monotonic() + 3
while True:
    pending = json.loads(subprocess.check_output(["syq", "recv", "pending", "--json"]))
    if not pending: break
    assert time.monotonic() < deadline, pending
    time.sleep(.05)
PYWAIT
if syq recv approve "$request_id"; then echo 'disconnected request was approved' >&2; exit 1; fi
test ! -e "$receive_root/disconnected"

printf 'case: changing policy cancels a pending request\n'
timeout 20 ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as cancelled-policy' &
return_copy_pid=$!
syq recv pending --wait --timeout 10 --json > /tmp/syq-pending.json
request_id=$(python3 -c 'import json; print(json.load(open("/tmp/syq-pending.json"))[0]["id"])')
syq recv on --notify off
if wait "$return_copy_pid"; then echo 'cancelled copy succeeded' >&2; exit 1; else test "$?" -ne 124; fi
return_copy_pid=
syq recv wait source --timeout 30
if syq recv approve "$request_id"; then echo 'cancelled request was approved' >&2; exit 1; fi
test ! -e "$receive_root/cancelled-policy"

printf 'case: native Linux notification actions control return copies\n'
dbus-run-session -- python3 /usr/local/libexec/syq-test-receive-notifications.py

python3 /usr/local/libexec/syq-test-forward-copy.py

printf 'case: explicit automatic approval supports unattended copies\n'
syq recv on --approve always
syq recv wait source --timeout 30
ssh source 'test -z "${SSH_AUTH_SOCK:-}"; syq cp --preserve permissions --srcs-in /tmp/syq-real-ssh/return-source --to laptop --into first'
remote_manifest source /tmp/syq-real-ssh/return-source /tmp/syq-return-source.manifest
(
    cd "$receive_root/first"
    {
        find . -mindepth 1 -printf '%y %m %p -> %l\n'
        find . -type f -exec sha256sum {} +
    } | LC_ALL=C sort
) > /tmp/syq-return-local.manifest
diff -u /tmp/syq-return-source.manifest /tmp/syq-return-local.manifest
ssh source 'syq cp --verify-only --srcs-in /tmp/syq-real-ssh/return-source --to @laptop --into first'
ssh source 'syq cp --ignore-existing /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as first/message.txt'

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

printf 'case: duplicate named return cannot displace the existing laptop\n'
(
    export XDG_RUNTIME_DIR=/tmp/syq-duplicate-runtime XDG_CONFIG_HOME=/tmp/syq-duplicate-config
    mkdir -p "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
    trap 'syq persist off' EXIT
    syq persist on
    syq recv on --name laptop --root /tmp/syq-real-ssh-receive-other
    syq cp --from source --srcs-in /tmp/syq-real-ssh/return-source --into /tmp/syq-duplicate-pull
    if syq recv wait source --timeout 5; then
        echo 'duplicate named destination unexpectedly succeeded' >&2
        exit 1
    fi
    syq recv status --json | python3 -c 'import json,sys; states=json.load(sys.stdin)["connections"]; assert any(s["connection"]["phase"] == "failed" and "already registered" in s["connection"]["error"] for s in states), states'
)
ssh source 'syq destination wait laptop --timeout 5'

printf 'case: interrupted named copy fails, laptop reconnects, and retry resumes\n'
ssh source 'dd if=/dev/urandom of=/tmp/syq-real-ssh/return-source/resume.bin bs=1M count=16 status=none'
source_prefix=$(ssh source 'dd if=/tmp/syq-real-ssh/return-source/resume.bin bs=1M count=4 status=none | sha256sum')
timeout 45 ssh source 'syq cp --bwlimit 512 /tmp/syq-real-ssh/return-source/resume.bin --to @laptop --as interrupted' &
return_copy_pid=$!
deadline=$(($(date +%s) + 25))
next_progress=$(($(date +%s) + 5))
while :; do
    partial_count=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-part.*' | wc -l)
    if [ "$partial_count" -eq 1 ]; then
        partial=$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-part.*')
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
receive_wrapper=$(syq recv status --json | python3 -c 'import json,sys; print(next(s["connection"]["ssh_pid"] for s in json.load(sys.stdin)["connections"] if s["endpoint"] == "source"))')
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
ssh source 'syq destination wait laptop --timeout 30'
ssh source 'syq cp /tmp/syq-real-ssh/return-source/resume.bin --to @laptop --as interrupted'
ssh source 'cat /tmp/syq-real-ssh/return-source/resume.bin' | cmp - "$receive_root/interrupted"
test "$(find "$receive_root" -maxdepth 1 -type f -name '.interrupted.syq-part.*' | wc -l)" -eq 0
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-reconnect'
printf 'return\n' | cmp - "$receive_root/after-reconnect"
printf 'case: return heartbeat timeout reconnects without toggling persistence\n'
python3 - <<'PYTEST'
import json
import os
import signal
import subprocess
import time

state = json.loads(subprocess.check_output(["syq", "recv", "status", "--json"]))
wrapper = next(s["connection"]["ssh_pid"] for s in state["connections"] if s["endpoint"] == "source")
transport = int(subprocess.check_output(["pgrep", "-P", str(wrapper), "-x", "ssh"]))
# Pause the real client so the server can open its forwarded socket but cannot
# receive a heartbeat reply. This produces a server-side socket timeout, unlike
# killing SSH, which usually gives the client a transport exit status of 255.
os.kill(transport, signal.SIGSTOP)
try:
    deadline = time.monotonic() + 40
    while True:
        result = subprocess.run(["ssh", "source", "test ! -e ~/.syq-destinations-v2/laptop.json"], timeout=5)
        if result.returncode == 0:
            break
        assert result.returncode == 1, result.returncode
        assert time.monotonic() < deadline, "heartbeat deadline: old registration still advertised"
        print("waiting for the paused return connection's heartbeat to time out", flush=True)
        time.sleep(2)
finally:
    os.kill(transport, signal.SIGCONT)
subprocess.run(["ssh", "source", "syq destination wait laptop --timeout 40"], check=True, timeout=45)
subprocess.run(["syq", "recv", "wait", "source", "--timeout", "10"], check=True, timeout=15)
with open("/tmp/syq-real-ssh-ssh.trace") as trace:
    ends = [dict(field.split("=", 1) for field in line.strip().split("\t")) for line in trace if line.startswith("phase=end\t")]
assert any(row["pid"] == str(wrapper) and row["status"] == "75" for row in ends), "heartbeat did not report retry status 75"
print("return connection recovered after the server heartbeat timed out", flush=True)
PYTEST
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-heartbeat-timeout'
printf 'return\n' | cmp - "$receive_root/after-heartbeat-timeout"
printf 'case: cwd permits destinations outside its starting directory\n'
syq recv on --cwd "$receive_root"
syq recv wait source --timeout 30
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as ../syq-return-outside'
printf 'return\n' | cmp - /tmp/syq-return-outside
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as /tmp/syq-return-absolute'
printf 'return\n' | cmp - /tmp/syq-return-absolute
printf 'case: recv off/on keeps ordinary persistence and restarts receiving\n'
syq recv off
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as while-disabled'; then
    echo 'disabled receiving unexpectedly accepted a transfer' >&2
    exit 1
fi
syq recv on
syq recv wait source --timeout 30
ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to laptop --as reenabled'
printf 'return\n' | cmp - "$receive_root/reenabled"
printf 'case: persistence off stops background receiving\n'
syq persist off
if ssh source 'syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as after-stop'; then
    echo 'stopped receiver unexpectedly accepted a transfer' >&2
    exit 1
fi
test ! -e "$receive_root/after-stop"
ssh source 'test ! -e ~/.syq-destinations-v2/laptop.json'
# Unrelated pooling scenarios count SSH commands; explicitly disable receiving.
syq recv off
syq completion cache clear >/dev/null

printf 'case: shell completion adapters parse and keep descriptions separate\n'
for completion_shell in bash zsh fish; do
    python3 /usr/local/libexec/syq-test-completion-display.py --syq /usr/local/bin/syq --shell "$completion_shell"
done
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
syq persist status | grep -q 'session pool' || {
    echo 'persist status does not show the session pool:' >&2
    syq persist status >&2
    exit 1
}
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
    if ! SYQ_DEBUG=1 syq cp --no-progress --results "$small_results" \
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

printf 'case: restricted enrollment refuses an SSH control-plane destination\n'
make_tree source /tmp/syq-real-ssh/protected-source protected
if protected_output=$(syq cp --no-progress -j 2 --preserve=permissions \
    --from source --srcs-in /tmp/syq-real-ssh/protected-source \
    --to destination --into /home/syq/.ssh/sender-controlled 2>&1); then
    echo 'copy into the restricted receiver control plane unexpectedly succeeded' >&2
    exit 1
fi
case "$protected_output" in
    *"protected SSH configuration directory"*) ;;
    *)
        echo 'control-plane refusal did not report the protected SSH directory:' >&2
        printf '%s\n' "$protected_output" >&2
        exit 1
        ;;
esac
ssh destination '
    test ! -e ~/.ssh/sender-controlled
    test ! -e ~/.local/share/syq/restricted
    test ! -e ~/.local/libexec/syq-receiver
'

printf 'case: source coordinator with constrained agent and restricted destination\n'
make_tree source /tmp/syq-real-ssh/direct-source direct
syq cp --no-progress -j 2 --preserve=permissions \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
assert_same_tree \
    source /tmp/syq-real-ssh/direct-source \
    destination /tmp/syq-real-ssh/direct-destination \
    direct

printf 'case: native verification and overwrite policies through the restricted receiver\n'
syq cp --verify-only --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh source 'printf source > /tmp/syq-real-ssh/direct-source/policy-file; printf new > /tmp/syq-real-ssh/direct-source/policy-new'
ssh destination 'printf destination > /tmp/syq-real-ssh/direct-destination/policy-file'
syq cp --ignore-existing --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = destination; test "$(cat /tmp/syq-real-ssh/direct-destination/policy-new)" = new; rm /tmp/syq-real-ssh/direct-destination/policy-new'
syq cp --existing --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = source; test ! -e /tmp/syq-real-ssh/direct-destination/policy-new'
policy_status=0
syq cp --verify-only --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination || policy_status=$?
test "$policy_status" -eq 23
ssh destination 'test ! -e /tmp/syq-real-ssh/direct-destination/policy-new'
policy_status=0
syq cp --update --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination || policy_status=$?
test "$policy_status" -ne 0
ssh source 'touch -m -d @1600000000 /tmp/syq-real-ssh/direct-source/policy-file'
ssh destination 'printf newer > /tmp/syq-real-ssh/direct-destination/policy-file; touch -m -d @1700000000 /tmp/syq-real-ssh/direct-destination/policy-file'
syq cp --update --coordinate-at local --no-progress -j 2 \
    --from source --srcs-in /tmp/syq-real-ssh/direct-source \
    --to destination --into /tmp/syq-real-ssh/direct-destination
ssh destination 'test "$(cat /tmp/syq-real-ssh/direct-destination/policy-file)" = newer; test -e /tmp/syq-real-ssh/direct-destination/policy-new'

printf 'case: destination firewall triggers automatic TCP fallback to SSH\n'
make_tree source /tmp/syq-real-ssh/firewall-source firewall
syq cp --no-progress -j 2 --preserve=permissions \
    --peer-auth broker --tcp-ports "$blocked_tcp_port-$blocked_tcp_port" \
    --from source --srcs-in /tmp/syq-real-ssh/firewall-source \
    --to destination --into /tmp/syq-real-ssh/firewall-destination
assert_same_tree \
    source /tmp/syq-real-ssh/firewall-source \
    destination /tmp/syq-real-ssh/firewall-destination \
    firewall

printf 'case: source coordinator with constrained agent and SSH data channels\n'
make_tree source /tmp/syq-real-ssh/ssh-source ssh
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
    --peer-auth broker \
    --from source --srcs-in /tmp/syq-real-ssh/ssh-source \
    --to destination --into /tmp/syq-real-ssh/ssh-destination
assert_same_tree \
    source /tmp/syq-real-ssh/ssh-source \
    destination /tmp/syq-real-ssh/ssh-destination \
    ssh

printf 'case: destination coordinator with the reversed constrained-agent edge\n'
make_tree source /tmp/syq-real-ssh/pull-source pull
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
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
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
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
        --as "/tmp/syq-real-ssh/tuning-$transport" -j 1 --no-progress \
        --bwlimit 8M --tuning-options "$tuning" "$@"
    syq cp --from source "/tmp/syq-real-ssh/tuning-$transport" \
        --as "/tmp/syq-real-ssh-tuning-$transport-download" -j 1 --no-progress \
        --bwlimit 8M --tuning-options "$tuning" "$@"
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
        -j 1 --no-progress --bwlimit 8M --tuning-options "$tuning" "$@"
    ssh destination sh -s -- "$coordinator" > /tmp/syq-real-ssh-tuning-check <<'EOF'
cat "/tmp/syq-real-ssh/tuning-$1"
EOF
    cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-tuning-check
done

printf 'case: experimental streaming over TCP/SSH and each coordinator\n'
streaming=copy-path=streaming,request-size=128K,split-min-size=1M,bw-pacing=average
for transport in tcp ssh; do
    if [ "$transport" = ssh ]; then set -- --no-tcp; else set --; fi
    timeout --kill-after=5s 25s syq cp /tmp/syq-real-ssh-tuning.bin --to source \
        --as "/tmp/syq-real-ssh/streaming-$transport" -j 2 --no-progress \
        --bwlimit 8M --tuning-options "$streaming" "$@"
    timeout --kill-after=5s 25s syq cp --from source "/tmp/syq-real-ssh/streaming-$transport" \
        --as "/tmp/syq-real-ssh-streaming-$transport-download" -j 2 --no-progress \
        --bwlimit 8M --tuning-options "$streaming" "$@"
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
        -j 2 --no-progress --bwlimit 8M --tuning-options "$streaming" "$@"
    ssh destination sh -s -- "$coordinator" > /tmp/syq-real-ssh-streaming-check <<'EOF'
cat "/tmp/syq-real-ssh/streaming-$1"
EOF
    cmp /tmp/syq-real-ssh-tuning.bin /tmp/syq-real-ssh-streaming-check
done

printf 'case: batch overrides through a command-restricted receiver\n'
ssh source 'mkdir /tmp/syq-real-ssh/tuning-batches; for n in 1 2 3 4 5 6 7; do dd if=/dev/urandom of=/tmp/syq-real-ssh/tuning-batches/$n bs=1024 count=600 status=none; done'
syq cp --from source --srcs-in /tmp/syq-real-ssh/tuning-batches \
    --to destination --into /tmp/syq-real-ssh/tuning-batches -j 1 --no-progress \
    --tuning-options batch-files=3,batch-bytes=1M
assert_same_tree source /tmp/syq-real-ssh/tuning-batches \
    destination /tmp/syq-real-ssh/tuning-batches tuning-batches

if ssh source 'pgrep -x syq >/dev/null' || ssh destination 'pgrep -x syq >/dev/null'; then
    echo 'a remote syq process survived the attached test suite' >&2
    exit 1
fi

printf 'real-SSH smoke suite passed\n'

# Exercise the user-facing script against real remote rsync and syq helpers.
# Quoted scratch names must survive both SSH and rsync's remote argument parsing.
benchmark_parent="$home/benchmark scratch's"
mkdir "$benchmark_parent"
ssh destination "mkdir -p \"/tmp/benchmark scratch's\""
for benchmark_mode in push pull; do
    bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload both --size quick \
        --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's"
done
# Automatic sizing uses the real terminal timing from each remote direction.
for benchmark_mode in push pull; do
    bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload small \
        --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's"
done
test -z "$(find "$benchmark_parent" -mindepth 1 -print)"
ssh destination 'test -z "$(find "/tmp/benchmark scratch'"'"'s" -mindepth 1 -print)"'
rmdir "$benchmark_parent"
ssh destination "rmdir \"/tmp/benchmark scratch's\""
echo 'interactive benchmark push/pull passed'

# Interrupt a real copy after the remote partial file appears, then require all
# temporary data to be gone. An unrelated file in the scratch parent must stay.
cancel_parent=$home/benchmark-cancel
mkdir "$cancel_parent"
ssh destination 'mkdir /tmp/benchmark-cancel; printf keep > /tmp/benchmark-cancel/keep'
bash /usr/local/libexec/syq-try-benchmark --yes --mode push --host destination \
    --workload large --size quick --rounds 1 --source-dir "$cancel_parent" \
    --dest-dir /tmp/benchmark-cancel &
benchmark_pid=$!
attempt=0
copy_started=false
while [ "$attempt" -lt 30 ]; do
    if ssh destination 'for file in /tmp/benchmark-cancel/syq-bench.*/trial/.data.syq-part.*; do
        if [ -f "$file" ]; then exit 0; fi
    done; exit 1'; then
        copy_started=true
        break
    fi
    if [ $((attempt % 5)) -eq 0 ]; then
        printf 'Waiting for remote benchmark partial file (%ss of 30s)...\n' "$attempt"
    fi
    sleep 1
    attempt=$((attempt + 1))
done
kill -TERM "$benchmark_pid" 2>/dev/null || true
benchmark_status=0
wait "$benchmark_pid" || benchmark_status=$?
if [ "$copy_started" != true ]; then
    echo 'benchmark cancellation timed out after 30s: no remote partial file observed' >&2
    exit 1
fi
test "$benchmark_status" -eq 143
test -z "$(find "$cancel_parent" -mindepth 1 -print)"
ssh destination 'test "$(cat /tmp/benchmark-cancel/keep)" = keep &&
    test "$(find /tmp/benchmark-cancel -mindepth 1 -maxdepth 1 | wc -l)" -eq 1'
rmdir "$cancel_parent"
ssh destination 'rm /tmp/benchmark-cancel/keep; rmdir /tmp/benchmark-cancel'
echo 'interactive benchmark remote interruption cleanup passed'
