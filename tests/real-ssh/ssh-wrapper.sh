#!/bin/sh
# Trace only transport-selection options while delegating every connection to OpenSSH.
set -u

control_master='unset'
control_path='unset'
host='unset'
next_is_control_path=false
next_is_host=false
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

trace=/tmp/syq-real-ssh-ssh.trace
printf 'phase=start\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" >>"$trace"
if [ "$strict_mux" = yes ]; then
    # A live control socket is tried first. If sshd rejects that channel,
    # prevent OpenSSH from hiding the rejection with its own direct fallback.
    /usr/bin/ssh -o ProxyCommand=false "$@"
else
    /usr/bin/ssh "$@"
fi
status=$?
printf 'phase=end\tpid=%s\thost=%s\tcontrol_master=%s\tcontrol_path=%s\tcontrol_socket=%s\tstrict_mux=%s\tstatus=%s\n' \
    "$$" "$host" "$control_master" "$control_path" "$control_socket" "$strict_mux" "$status" >>"$trace"
exit "$status"
