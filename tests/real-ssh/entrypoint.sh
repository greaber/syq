#!/bin/sh
set -eu

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
    if [ "${SYQ_REAL_SSH_RETURN_FORWARDING:-0}" = 1 ]; then
        # OpenSSH 9.2 gates remote Unix sockets on TCP forwarding as well.
        # Only the source needs return forwarding; the destination keeps it disabled.
        printf 'AllowTcpForwarding remote\nAllowStreamLocalForwarding remote\n' > /etc/ssh/sshd_config.d/00-return.conf
    fi
    /usr/sbin/sshd -t -f /etc/ssh/sshd_config
    if [ -n "${SYQ_REAL_SSH_EXPECT_MAX_SESSIONS:-}" ]; then
        effective_max_sessions=$(
            /usr/sbin/sshd -T -f /etc/ssh/sshd_config |
                awk '$1 == "maxsessions" { print $2 }'
        )
        test "$effective_max_sessions" = "$SYQ_REAL_SSH_EXPECT_MAX_SESSIONS"
    fi
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
