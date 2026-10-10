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
restricted_worker=no
return_receiver=no
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
        *--restricted-worker=*) restricted_worker=yes ;;
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
printf 'phase=start\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\treturn_receiver=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" "$return_receiver" >>"$trace"
if [ "$restricted_worker" = yes ] && [ -f /tmp/syq-real-ssh-block-restricted-workers ]; then
    printf 'restricted SSH worker blocked by the route test\n' >&2
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
printf 'phase=end\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\tstatus=%s\treturn_receiver=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" "$status" "$return_receiver" >>"$trace"
exit "$status"
