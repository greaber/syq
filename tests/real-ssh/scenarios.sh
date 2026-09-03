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
dd if=/dev/zero of="$root/subdir/chunks.bin" bs=1M count=6 status=none
chmod 0640 "$root/message.txt" "$root/subdir/chunks.bin"
ln -s message.txt "$root/link"
EOF
}

printf 'real-SSH environment: profile %s; %s; %s\n' \
    "${SYQ_REAL_SSH_PROFILE:-default}" "$(syq --build-identity)" "$(ssh -V 2>&1)"

printf 'case: source coordinator with constrained agent and restricted destination\n'
make_tree source /tmp/syq-real-ssh/direct-source direct
ssh destination 'install -d -m 0755 /tmp/syq-real-ssh/direct-destination'
syq cp --no-progress -j 2 --preserve=permissions \
    --from source --src-src /tmp/syq-real-ssh/direct-source \
    --to destination --into-existing /tmp/syq-real-ssh/direct-destination
assert_same_tree \
    source /tmp/syq-real-ssh/direct-source \
    destination /tmp/syq-real-ssh/direct-destination \
    direct

printf 'case: destination firewall triggers automatic TCP fallback to SSH\n'
make_tree source /tmp/syq-real-ssh/firewall-source firewall
syq cp --no-progress -j 2 --preserve=permissions \
    --agent-broker-only --tcp-ports "$blocked_tcp_port-$blocked_tcp_port" \
    --from source --src-src /tmp/syq-real-ssh/firewall-source \
    --to destination --into /tmp/syq-real-ssh/firewall-destination
assert_same_tree \
    source /tmp/syq-real-ssh/firewall-source \
    destination /tmp/syq-real-ssh/firewall-destination \
    firewall

printf 'case: source coordinator with constrained agent and SSH data channels\n'
make_tree source /tmp/syq-real-ssh/ssh-source ssh
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
    --agent-broker-only \
    --from source --src-src /tmp/syq-real-ssh/ssh-source \
    --to destination --into /tmp/syq-real-ssh/ssh-destination
assert_same_tree \
    source /tmp/syq-real-ssh/ssh-source \
    destination /tmp/syq-real-ssh/ssh-destination \
    ssh

printf 'case: destination coordinator with the reversed constrained-agent edge\n'
make_tree source /tmp/syq-real-ssh/pull-source pull
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
    --agent-broker-only --coordinate-at dest \
    --from source --src-src /tmp/syq-real-ssh/pull-source \
    --to destination --into /tmp/syq-real-ssh/pull-destination
assert_same_tree \
    source /tmp/syq-real-ssh/pull-source \
    destination /tmp/syq-real-ssh/pull-destination \
    pull

printf 'case: local coordinator relaying between two SSH endpoints\n'
make_tree source /tmp/syq-real-ssh/relay-source relay
syq cp --no-progress --no-tcp -j 2 --preserve=permissions \
    --coordinate-at local \
    --from source --src-src /tmp/syq-real-ssh/relay-source \
    --to destination --into /tmp/syq-real-ssh/relay-destination
assert_same_tree \
    source /tmp/syq-real-ssh/relay-source \
    destination /tmp/syq-real-ssh/relay-destination \
    relay

if ssh source 'pgrep -x syq >/dev/null' || ssh destination 'pgrep -x syq >/dev/null'; then
    echo 'a remote syq process survived the attached test suite' >&2
    exit 1
fi

printf 'real-SSH smoke suite passed\n'
