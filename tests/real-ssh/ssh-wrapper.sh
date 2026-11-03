#!/bin/sh
# Trace only transport-selection options while delegating every connection to OpenSSH.
set -u

# Only the compatibility case selects the old client, in its isolated lab.
ssh_client=/usr/bin/ssh
if [ -f /tmp/syq-real-ssh-legacy-client ]; then
    ssh_client=/opt/openssh-8.8/bin/ssh
fi

control_master='unset'
control_path='unset'
host='unset'
next_is_control_path=false
next_is_host=false
entry_key=no
query=no
return_receiver=no
enrollment=no
direct=no
jump=no
for argument do
    if [ "$next_is_host" = true ]; then
        host=$argument
        next_is_host=false
        continue
    fi
    if [ "$next_is_control_path" = true ]; then
        control_path=$argument
        next_is_control_path=false
        continue
    fi
    case "$argument" in
        ControlMaster=*) control_master=${argument#ControlMaster=} ;;
        ControlPath=*) control_path=${argument#ControlPath=} ;;
        IdentityFile=*/entry-key) entry_key=yes ;;
        -G) query=yes ;;
        # Only the login that enrolls a destination asks for this.
        FingerprintHash=sha256) enrollment=yes ;;
        ProxyJump=none) direct=yes ;;
        -W) jump=yes ;;
        *--return-receiver*) return_receiver=yes ;;
        -S) next_is_control_path=true ;;
        --) next_is_host=true ;;
    esac
done

control_socket=absent
if [ "$control_path" != none ] && [ "$control_path" != unset ] && [ -S "$control_path" ]; then
    control_socket=present
fi
strict_mux=no
if [ "${SYQ_REAL_SSH_STRICT_MUX_FAILURE:-0}" = 1 ] &&
    [ "$host" = destination ] &&
    [ "$control_master" = no ] &&
    [ "$control_path" != none ] &&
    [ "$control_path" != unset ] &&
    [ "$control_socket" = present ]; then
    strict_mux=yes
fi

trace=${SYQ_REAL_SSH_TRACE_FILE:-/tmp/syq-real-ssh-ssh.trace}
# Append fields so positional readers of the existing columns remain valid.
printf 'phase=start\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\treturn_receiver=%s\tentry_key=%s\tquery=%s\tenrollment=%s\tdirect=%s\tjump=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" "$return_receiver" "$entry_key" "$query" "$enrollment" "$direct" "$jump" >>"$trace"
# The route test slows this machine's reading of the destination's SSH
# configuration, so that approving a copy takes a while.
if [ "$query" = yes ] && [ "$host" = destination ] && [ -f /tmp/syq-real-ssh-slow-config ]; then
    sleep 10
fi
# Every connection to an enrolled receiver uses its entry key. The copy's
# control connects first and its workers after it, so while the route test
# blocks workers, the first of these connections passes and the rest fail.
blocked=no
blocked_message='restricted SSH worker blocked by the route test'
if [ "$entry_key" = yes ] && [ -f /tmp/syq-real-ssh-block-restricted-workers ]; then
    if [ -e /tmp/syq-real-ssh-block-restricted-workers.control ]; then
        blocked=yes
    else
        : >/tmp/syq-real-ssh-block-restricted-workers.control
    fi
fi
# The slot test holds a copy's workers the same way until it removes the
# file, so that they start while other sessions hold the receiver's slots.
if [ "$entry_key" = yes ] && [ -f /tmp/syq-real-ssh-hold-restricted-workers ]; then
    if [ -e /tmp/syq-real-ssh-hold-restricted-workers.control ]; then
        : >/tmp/syq-real-ssh-hold-restricted-workers.waiting
        waited=0
        while [ -f /tmp/syq-real-ssh-hold-restricted-workers ] && [ "$waited" -lt 600 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
    else
        : >/tmp/syq-real-ssh-hold-restricted-workers.control
    fi
fi
# The setup test holds the laptop's enrolling login, as a destination that
# stopped answering would, until it removes the file.
if [ "$enrollment" = yes ] && [ "$query" = no ] && [ -f /tmp/syq-real-ssh-hold-enrollment ]; then
    printf '%s\n' "$$" >/tmp/syq-real-ssh-hold-enrollment.waiting
    waited=0
    while [ -f /tmp/syq-real-ssh-hold-enrollment ] && [ "$waited" -lt 1200 ]; do
        sleep 0.1
        waited=$((waited + 1))
    done
fi
# The fallback test makes the destination unreachable from the laptop
# directly, and sends the jump through the server that asked to a listener
# that permits it.
if [ "$enrollment" = yes ] && [ "$direct" = yes ] && [ "$query" = no ] &&
    [ -f /tmp/syq-real-ssh-unreachable-direct ]; then
    blocked_message="ssh: connect to host $host port 22: Network is unreachable"
    blocked=yes
fi
if [ "$jump" = yes ] && [ -f /tmp/syq-real-ssh-jump-port ]; then
    set -- -o "Port=$(cat /tmp/syq-real-ssh-jump-port)" "$@"
fi
if [ "$blocked" = yes ]; then
    printf '%s\n' "$blocked_message" >&2
    status=255
elif [ "$strict_mux" = yes ]; then
    # A live control socket is tried first. If sshd rejects that channel,
    # prevent OpenSSH from hiding the rejection with its own direct fallback.
    "$ssh_client" -o ProxyCommand=false "$@"
    status=$?
else
    "$ssh_client" "$@"
    status=$?
fi
printf 'phase=end\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\tstatus=%s\treturn_receiver=%s\tentry_key=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" "$status" "$return_receiver" "$entry_key" >>"$trace"
exit "$status"
