#!/bin/sh
set -eu

endpoint() {
    test -r /run/lab/authorized_keys
    # The mounted key keeps the host account's UID, which may belong to any
    # account in this image. sshd's StrictModes accepts a root-owned copy.
    install -m 0644 -o root -g root /run/lab/authorized_keys /etc/ssh/lab_authorized_keys
    install -d -m 0700 -o syq -g syq /home/syq/.ssh
    # Give the second test account its own correctly owned copy as well.
    long_home=$(getent passwd longhome | cut -d: -f6)
    install -d -m 0700 -o longhome -g syq "$long_home/.ssh"
    install -m 0600 -o longhome -g syq /run/lab/authorized_keys "$long_home/.ssh/authorized_keys"
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
    if [ "${SYQ_REAL_SSH_SUITE:-core}" = core ] && [ "${SYQ_REAL_SSH_ROOT_SECURITY:-1}" = 1 ]; then
        python3 /usr/local/libexec/syq-test-root-security.py
    fi
    test -r /run/lab/id_ed25519
    install -d -m 0700 -o syq -g syq /home/syq/.ssh
    install -m 0600 -o syq -g syq /run/lab/id_ed25519 /home/syq/.ssh/id_ed25519
    if [ "${SYQ_REAL_SSH_SUITE:-core}" = core ]; then
        # A separate unprivileged requester on the runner gives bridge tests
        # four roles without another container or access to the laptop's key.
        install -d -m 0755 /run/sshd
        ssh-keygen -y -f /home/syq/.ssh/id_ed25519 > /etc/ssh/lab_authorized_keys
        chmod 0644 /etc/ssh/lab_authorized_keys
        ssh-keygen -q -t ed25519 -N '' -f /run/sshd/ssh_host_ed25519_key
        sed 's/ListenAddress 0.0.0.0/ListenAddress 127.0.0.1/' \
            /etc/ssh/sshd_config > /run/sshd/requester_config
        printf 'AllowTcpForwarding remote\nAllowStreamLocalForwarding remote\n' \
            > /etc/ssh/sshd_config.d/00-return.conf
        /usr/sbin/sshd -t -f /run/sshd/requester_config
        /usr/sbin/sshd -e -f /run/sshd/requester_config
    fi
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
