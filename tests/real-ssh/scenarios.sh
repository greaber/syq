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
test "$(direct_logins)" -eq 1
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
test -z "$(find "$benchmark_parent" -mindepth 1 -print)"
ssh destination 'test -z "$(find "/tmp/benchmark scratch'"'"'s" -mindepth 1 -print)"'
rmdir "$benchmark_parent"
ssh destination "rmdir \"/tmp/benchmark scratch's\""
echo 'interactive benchmark push/pull passed'
