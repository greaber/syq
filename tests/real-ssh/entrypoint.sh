#!/bin/sh
set -eu

seed_helper() {
    identity=$(syq --build-identity)
    case "$(uname -m)" in
        x86_64) target=linux-x86_64 ;;
        aarch64) target=linux-aarch64 ;;
        *)
            echo "unsupported real-SSH test architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
    helper="/home/syq/.cache/syq/helpers/${identity}-release-v1/${target}/syq"
    install -D -m 0755 -o syq -g syq /usr/local/bin/syq "$helper"
}

endpoint() {
    test -r /run/lab/authorized_keys
    install -d -m 0700 -o syq -g syq /home/syq/.ssh
    install -d -m 0755 /run/sshd
    ssh-keygen -q -t ed25519 -N '' -f /run/sshd/ssh_host_ed25519_key
    if [ -n "${SYQ_REAL_SSH_BLOCKED_TCP_PORT:-}" ]; then
        iptables -w -A INPUT -p tcp \
            --dport "$SYQ_REAL_SSH_BLOCKED_TCP_PORT" \
            -j REJECT --reject-with tcp-reset
        iptables -w -C INPUT -p tcp \
            --dport "$SYQ_REAL_SSH_BLOCKED_TCP_PORT" \
            -j REJECT --reject-with tcp-reset
    fi
    seed_helper
    /usr/sbin/sshd -t -f /etc/ssh/sshd_config
    exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
}

runner() {
    test -r /run/lab/id_ed25519
    install -d -m 0700 -o syq -g syq /home/syq/.ssh
    install -m 0600 -o syq -g syq /run/lab/id_ed25519 /home/syq/.ssh/id_ed25519
    exec runuser -u syq -- env \
        HOME=/home/syq \
        LOGNAME=syq \
        PATH=/usr/local/bin:/usr/bin:/bin \
        USER=syq \
        /usr/local/libexec/syq-real-ssh-scenarios
}

case "${1:-}" in
    endpoint) endpoint ;;
    runner) runner ;;
    *)
        echo 'usage: syq-real-ssh-entrypoint endpoint|runner' >&2
        exit 2
        ;;
esac
