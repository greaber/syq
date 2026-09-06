#!/usr/bin/env bash
# Standalone Linux/macOS benchmark. Bash 3.2 compatible; no syq-bench install.
set -euo pipefail
export LC_ALL=C
# Quote remote paths ourselves for both old (including macOS) and new rsync.
export RSYNC_OLD_ARGS=1
export RSYNC_RSH="ssh -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3"

usage() {
    cat <<'HELP'
Compare syq with rsync, and cp for local copies, using disposable synthetic data.

Usage: bash try-benchmark.sh [OPTIONS]
Without --yes, unanswered choices are prompted through /dev/tty (also with curl | bash).

  --mode local|push|pull    Copy locally, to an SSH host, or from an SSH host
  --host USER@HOST          SSH host or config alias (configure ports in ~/.ssh/config)
  --workload large|small|both
  --size quick|medium|large Quick: 64 MiB + 1,024 files; medium: 1 GiB + 4,096;
                           large: 8 GiB + 16,384. Small files are 8 KiB each.
  --source-dir DIR         Local scratch parent (default: current directory)
  --dest-dir DIR           Destination scratch parent (default: current directory)
                           For push/pull this is the REMOTE scratch parent.
                           For pull, --source-dir is the local destination parent.
  --rounds N               Trials per tool/workload, rotating order (default: 3)
  --install                Install syq locally if missing, using its official installer
  --yes                    Use defaults for unspecified choices; do not prompt
  --help                   Show this help

Requires Bash, rsync, OpenSSL, and standard Unix utilities locally; terminal runs
also need Perl (for terminal process-group control). Remote tests
also need SSH locally and rsync plus standard utilities on the remote host.
Only newly created syq-bench.* directories are used. Existing data is not copied.
HELP
}
fail() { printf 'Benchmark: %s\n' "$*" >&2; exit 1; }
quote() { printf '%s\n' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/"; }
ask() {
    local answer
    printf '%s [%s]: ' "$1" "$2" >&2
    IFS= read -r answer <&3 || fail 'No answer received. Use --yes for noninteractive runs.'
    REPLY=${answer:-$2}
}
need() { command -v "$1" >/dev/null || fail "Missing required command: $1"; }
remote() { ssh -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 "$host" "$1"; }

# Background jobs have their own process groups, so interruption stops the whole
# local copy/generation group before cleanup. Remote cleanup first moves scratch
# out of the transfer path; all copies require existing destination parents.
active_pid=
terminal_pgid=
local_root=
dest_root=
remote_root=
host=
group_running() {
    local states
    states=$(ps -eo pgid=,stat=) || return 0
    # A zombie cannot write or hold files open. It may await reaping by init.
    awk -v group="$active_pid" '$1 == group && $2 !~ /^Z/ {live=1} END {exit !live}' <<< "$states"
}
terminal_group() {
    # Bash's fg builtin defers signal traps. Hand off only terminal ownership,
    # leaving the shell free to use its interruptible wait builtin.
    perl -MPOSIX -e '
        $SIG{TTOU} = "IGNORE";
        if (POSIX::tcsetpgrp(3, $ARGV[0]) != 0) {
            my $error = "$!";
            # A very short job can finish before the handoff.
            exit 0 if !kill(0, -$ARGV[0]) && $! == POSIX::ESRCH();
            die "terminal process group: $error\n";
        }
    ' "$1"
}
cleanup() {
    local status=$? attempt
    trap - EXIT INT TERM HUP
    [[ -z $terminal_pgid ]] || terminal_group "$terminal_pgid" || :
    if [[ -n $active_pid ]]; then
        printf 'Stopping benchmark workers...\n' >&2
        kill -TERM -- "-$active_pid" 2>/dev/null || :
        # A background terminal reader may have stopped on SIGTTIN.
        kill -CONT -- "-$active_pid" 2>/dev/null || :
        for ((attempt=0; attempt<10; attempt++)); do
            group_running || break
            sleep 0.1
        done
        if group_running; then
            kill -KILL -- "-$active_pid" 2>/dev/null || :
            for ((attempt=0; attempt<20; attempt++)); do
                group_running || break
                sleep 0.1
            done
        fi
        if group_running; then
            printf 'Workers still exist; scratch preserved: %s %s\n' "$local_root" "$dest_root" >&2
            exit 1
        fi
        wait "$active_pid" 2>/dev/null || :
    fi
    if [[ -n $remote_root ]]; then
        printf 'Cleaning up remote benchmark files...\n'
        # Fence the original path before removing files. syq requires an existing
        # destination; rsync cannot create missing intermediate parents. Thus a
        # late remote operation cannot recreate the tree under its old name.
        if ! remote "set -eu
root=$(quote "$remote_root")
[ -d \"\$root\" ] || exit 0
cleanup_dir=\$(mktemp -d \"\$root.cleanup.XXXXXXXX\")
trap 'printf \"Remote cleanup incomplete: %s and %s\\n\" \"\$root\" \"\$cleanup_dir\" >&2' HUP INT TERM
if mv \"\$root\" \"\$cleanup_dir/data\" && rm -rf \"\$cleanup_dir\"; then
    trap - HUP INT TERM
else
    printf 'Remote cleanup incomplete: %s and %s\\n' \"\$root\" \"\$cleanup_dir\" >&2
    exit 1
fi"; then
            printf 'Could not finish remote cleanup: %s:%s (also check sibling .cleanup.* directories).\n' "$host" "$remote_root" >&2
            [[ $status -ne 0 ]] || status=1
        fi
    fi
    [[ -z $dest_root ]] || rm -rf -- "$dest_root" || status=1
    [[ -z $local_root ]] || rm -rf -- "$local_root" || status=1
    exit "$status"
}
run() {
    "$@" &
    active_pid=$!
    local status=0
    # Disable job-status waits after assigning the job its own process group:
    # wait must wait for exit, including if an early terminal read stopped it.
    set +m
    if [[ -n $terminal_pgid ]]; then
        terminal_group "$active_pid" || status=$?
        kill -CONT -- "-$active_pid" 2>/dev/null || :
    fi
    [[ $status -eq 0 ]] || return "$status"
    wait "$active_pid" || status=$?
    [[ -z $terminal_pgid ]] || terminal_group "$terminal_pgid"
    set -m
    [[ $status -ne 130 && $status -ne 143 ]] || exit "$status"
    # Preserve the group ID on failure so EXIT can also stop surviving children.
    [[ $status -eq 0 ]] || return "$status"
    active_pid=
}
manifest() { (cd "$1"; for file in *; do cksum "$file"; done); }
remote_manifest() { remote "cd $(quote "$1") && for file in *; do cksum \"\$file\" || exit; done"; }

make_data() {
    local workload=$1 amount=$2
    mkdir "$local_root/$workload"
    # Fixed AES-CTR stream: deterministic, dense and effectively incompressible.
    # No keys or user data are involved. Generation is outside measured time.
    if [[ $workload == large ]]; then
        dd if=/dev/zero bs=1048576 count="$amount" 2>/dev/null |
            openssl enc -aes-256-ctr -nosalt -K "$key" -iv "$iv" > "$local_root/$workload/data"
    else
        dd if=/dev/zero bs=8192 count="$amount" 2>/dev/null |
            openssl enc -aes-256-ctr -nosalt -K "$key" -iv "$iv" |
            (cd "$local_root/$workload"; split -b 8192 -a 6 - file-)
    fi
}
copy_with() {
    local tool=$1 source=$2 destination=$3
    local command=() syq_options=(--stats)
    [[ ${4:-} != setup ]] || syq_options+=(--quiet)
    case $tool in
        syq)
            case $mode in
                local) command=(syq cp --preserve=permissions --srcs-in "$source" --into-existing "$destination" "${syq_options[@]}") ;;
                push) command=(syq cp --preserve=permissions --srcs-in "$source" --to "$host" --into-existing "$destination" "${syq_options[@]}") ;;
                pull) command=(syq cp --preserve=permissions --from "$host" --srcs-in "$source" --into-existing "$destination" "${syq_options[@]}") ;;
            esac ;;
        rsync)
            case $mode in
                local) command=(rsync -rpt -- "$source/" "$destination/") ;;
                push) command=(rsync -rpt -- "$source/" "$host:$(quote "$destination/")") ;;
                pull) command=(rsync -rpt -- "$host:$(quote "$source/")" "$destination/") ;;
            esac ;;
        cp) command=(cp -pR "$source/." "$destination/") ;;
    esac
    if [[ ${4:-} == show ]]; then
        printf 'Command:'
        printf ' %q' "${command[@]}"
        printf '\n'
    else
        "${command[@]}"
    fi
}
timed_copy() {
    # Separate Bash's timing output from the command's live stdout/stderr.
    copy_with "$@" show
    TIMEFORMAT='%R'
    { time copy_with "$@" 1>&4 2>&5; } 2> "$local_root/time"
}

main() {
    local mode='' workload='' size='' source_dir='' dest_dir='' rounds=3 yes=false install=false
    local option tool round index offset source destination case_name bytes seconds local_parent remote_parent
    local large_mib small_files
    local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    local iv=000102030405060708090a0b0c0d0e0f
    while [[ $# -gt 0 ]]; do
        option=$1
        case $option in
            --help|-h) usage; return ;;
            --yes) yes=true; shift; continue ;;
            --install) install=true; shift; continue ;;
            --mode|--host|--workload|--size|--source-dir|--dest-dir|--rounds)
                [[ $# -ge 2 && -n $2 ]] || fail "$option needs a value"
                case $option in
                    --mode) mode=$2 ;; --host) host=$2 ;; --workload) workload=$2 ;;
                    --size) size=$2 ;; --source-dir) source_dir=$2 ;; --dest-dir) dest_dir=$2 ;;
                    --rounds) rounds=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $option (see --help)" ;;
        esac
    done
    [[ -z $host || -n $mode ]] || mode=push
    printf 'Compare copies on your machines — no speedup is guaranteed.\n'
    if { exec 3</dev/tty; } 2>/dev/null; then
        : # Also allow SSH credential prompts when --yes supplies benchmark choices.
    elif ! $yes; then
        fail 'No terminal. Pass --yes and your choices (see --help).'
    fi
    if ! $yes; then
        if [[ -z $mode ]]; then ask 'Copy where? local / push / pull' local; mode=$REPLY; fi
        if [[ $mode != local && -z $host ]]; then ask 'SSH host or config alias' ''; host=$REPLY; fi
        if [[ -z $workload ]]; then ask 'Workloads? large / small / both' both; workload=$REPLY; fi
        if [[ -z $size ]]; then ask 'Size? quick (64 MiB + 8 MiB) / medium (1 GiB + 32 MiB) / large (8 GiB + 128 MiB)' quick; size=$REPLY; fi
        if [[ -z $source_dir ]]; then ask 'Local scratch parent' "$PWD"; source_dir=$REPLY; fi
        if [[ -z $dest_dir ]]; then
            if [[ $mode == local ]]; then ask 'Destination scratch parent (can be another disk or NFS mount)' "$source_dir"
            else ask 'Remote scratch parent (existing writable directory)' .; fi
            dest_dir=$REPLY
        fi
    fi
    mode=${mode:-local}; workload=${workload:-both}; size=${size:-quick}
    source_dir=${source_dir:-$PWD}; dest_dir=${dest_dir:-.}
    case $mode in local|push|pull) ;; *) fail 'Mode must be local, push or pull.' ;; esac
    case $workload in large|small|both) ;; *) fail 'Workload must be large, small or both.' ;; esac
    case $size in quick) large_mib=64; small_files=1024 ;; medium) large_mib=1024; small_files=4096 ;; large) large_mib=8192; small_files=16384 ;; *) fail 'Size must be quick, medium or large.' ;; esac
    [[ $rounds =~ ^[1-9]$ ]] || fail 'Rounds must be between 1 and 9.'
    for tool in bash rsync openssl dd split cksum cmp awk mktemp mkdir rm cat ps sleep sed; do need "$tool"; done
    [[ $mode != local ]] || need cp
    if [[ $mode != local ]]; then
        need ssh
        [[ $host =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.@-]*$ ]] || fail 'Use an SSH config alias or USER@HOST; configure ports/IPv6 in ~/.ssh/config.'
    fi
    # Reject newlines in scratch paths so diagnostics remain unambiguous.
    [[ $source_dir != *$'\n'* && $dest_dir != *$'\n'* ]] || fail 'Scratch paths cannot contain newlines.'
    if [[ -t 3 ]]; then
        need perl
        terminal_pgid=$(ps -o pgid= -p "$$")
    fi
    local_parent=$(cd -- "$source_dir" && pwd -P) || fail 'Local scratch parent must exist.'
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    set -m
    local_root=$(mktemp -d "$local_parent/syq-bench.XXXXXXXX")
    if ! command -v syq >/dev/null; then
        if ! $install && ! $yes; then ask 'syq is missing. Install the official release into ~/.local/bin? yes / no' no; [[ $REPLY != yes ]] || install=true; fi
        $install || fail 'Install syq first, or pass --install to use its official installer.'
        need curl
        run curl --proto '=https' --tlsv1.2 -fLsS https://github.com/greaber/syq/releases/latest/download/install.sh -o "$local_root/install.sh"
        run sh "$local_root/install.sh"
        export PATH="$HOME/.local/bin:$PATH"
        need syq
    fi
    printf '\nVersions:\n'
    printf 'syq: '
    syq --build-identity
    rsync --version | sed -n '1p'
    if [[ $mode == local ]]; then
        dest_dir=$(cd -- "$dest_dir" && pwd -P) || fail 'Destination scratch parent must exist.'
        dest_root=$(mktemp -d "$dest_dir/syq-bench.XXXXXXXX")
    else
        printf '\nChecking SSH access and remote tools (normal SSH authentication applies)...\n'
        remote 'command -v rsync >/dev/null && command -v cksum >/dev/null && command -v mktemp >/dev/null && rsync --version' | sed -n '1p' || fail 'Remote needs rsync, cksum and mktemp, and working SSH access.'
        [[ $dest_dir == /* ]] || dest_dir=./$dest_dir
        remote_parent=$(remote "cd $(quote "$dest_dir") && pwd -P")
        [[ $remote_parent == /* && $remote_parent != *$'\n'* ]] || fail 'Remote shell must print only the requested output.'
        remote_root=$(remote "mktemp -d $(quote "$remote_parent/syq-bench.XXXXXXXX")")
        [[ $remote_root == "$remote_parent/"syq-bench.* && $remote_root != *$'\n'* ]] || fail 'Unexpected remote scratch path.'
        dest_root=$(mktemp -d "$local_parent/syq-bench.XXXXXXXX")
    fi
    printf '\nMode: %s; workloads: %s; size: %s; rounds: %s\n' "$mode" "$workload" "$size" "$rounds"
    [[ $mode == local ]] || printf 'SSH host: %s\n' "$host"
    printf 'Local scratch: %s\n' "$local_root"
    if [[ $mode == local ]]; then printf 'Destination scratch: %s\n' "$dest_root"
    else printf 'Remote scratch: %s\n' "$remote_root"; fi
    printf 'Each trial uses an empty destination; order rotates. Setup and checksum verification are untimed.\n'
    printf 'Caches are NOT flushed; times include startup and buffered writes, not durable disk flushes.\n'
    printf 'Allow roughly twice the selected data size locally, plus one copy remotely for SSH tests.\n'
    printf 'Using syq defaults with permissions preserved, rsync -rpt, and local cp -pR.\n\n'
    exec 4>&1 5>&2
    local tools=(syq rsync) workloads=(large small)
    [[ $mode != local ]] || tools+=(cp)
    [[ $workload == both ]] || workloads=("$workload")
    : > "$local_root/results"
    for case_name in "${workloads[@]}"; do
        if [[ $case_name == large ]]; then printf 'Generating one %s MiB file...\n' "$large_mib"
        else printf 'Generating %s files of 8 KiB each...\n' "$small_files"; fi
        if [[ $case_name == large ]]; then run make_data large "$large_mib"; bytes=$((large_mib * 1048576))
        else run make_data small "$small_files"; bytes=$((small_files * 8192)); fi
        manifest "$local_root/$case_name" > "$local_root/expected"
        source=$local_root/$case_name
        if [[ $mode == pull ]]; then
            printf 'Staging source on remote host (untimed)...\n'
            run rsync -rpt -- "$source/" "$host:$(quote "$remote_root/$case_name/")"
            source=$remote_root/$case_name
            remote_manifest "$source" > "$local_root/actual"
            cmp "$local_root/expected" "$local_root/actual" || fail 'Remote staging verification failed.'
        fi
        if [[ $case_name == "${workloads[0]}" ]]; then
            # Do this once, not once per workload. Keep the measured copy's full
            # transport path, but suppress meaningless throughput for the 14-byte probe.
            printf 'Preparing syq with a 14-byte setup copy (not timed as a benchmark)...\n'
            mkdir "$local_root/probe"
            printf 'syq benchmark\n' > "$local_root/probe/data"
            if [[ $mode == pull ]]; then
                mkdir "$dest_root/probe"
                run rsync -rpt -- "$local_root/probe/" "$host:$(quote "$remote_root/probe/")"
                run copy_with syq "$remote_root/probe" "$dest_root/probe" setup
                rm -rf -- "$dest_root/probe"
            elif [[ $mode == push ]]; then
                remote "mkdir $(quote "$remote_root/probe")"
                run copy_with syq "$local_root/probe" "$remote_root/probe" setup
                remote "rm -rf $(quote "$remote_root/probe")"
            else
                mkdir "$dest_root/probe"
                run copy_with syq "$local_root/probe" "$dest_root/probe" setup
                rm -rf -- "$dest_root/probe"
            fi
            rm -rf -- "$local_root/probe"
            printf 'Setup complete.\n'
        fi
        for ((round=1; round<=rounds; round++)); do
            for ((offset=0; offset<${#tools[@]}; offset++)); do
                index=$(((round - 1 + offset) % ${#tools[@]}))
                tool=${tools[$index]}
                destination=$dest_root/trial
                if [[ $mode == push ]]; then destination=$remote_root/trial; remote "mkdir $(quote "$destination")"
                else mkdir "$destination"; fi
                printf '\n%s: %s, trial %s/%s (%s bytes)\n' "$case_name" "$tool" "$round" "$rounds" "$bytes"
                run timed_copy "$tool" "$source" "$destination" || fail "$tool failed; no successful result recorded for this trial."
                seconds=$(cat "$local_root/time")
                if [[ $mode == push ]]; then remote_manifest "$destination" > "$local_root/actual"
                else manifest "$destination" > "$local_root/actual"; fi
                cmp "$local_root/expected" "$local_root/actual" || fail "$tool destination content check failed."
                printf '%s %s %s %s\n' "$case_name" "$tool" "$seconds" "$bytes" >> "$local_root/results"
                printf 'Verified contents; elapsed %s seconds.\n' "$seconds"
                if [[ $mode == push ]]; then remote "rm -rf $(quote "$destination")"
                else rm -rf -- "$destination"; fi
            done
        done
        rm -rf -- "${local_root:?}/$case_name"
        [[ $mode != pull ]] || remote "rm -rf $(quote "$source") $(quote "$remote_root/probe")"
    done
    printf '\nResults (mean elapsed seconds; all completed copies checked with POSIX cksum):\n'
    awk '{key=$1 " " $2;
          if (!(key in n)) {order[++count]=key; low[key]=$3; high[key]=$3}
          total[key]+=$3; n[key]++;
          if ($3 < low[key]) low[key]=$3; if ($3 > high[key]) high[key]=$3}
         END {printf "%-18s %10s %10s %10s %8s\n", "Workload / tool", "Mean", "Min", "Max", "Trials";
              for (i=1; i<=count; i++) {key=order[i]; printf "%-18s %10.3f %10.3f %10.3f %8d\n", key, total[key]/n[key], low[key], high[key], n[key]}}' "$local_root/results"
    printf '\nA quick synthetic comparison, not a prediction for every workload.\n'
    printf 'Filesystem caching, cloning, network conditions and startup costs affect results.\n'
    printf 'Try larger data and your real workloads too. Resume and direct server copies are other reasons to use syq.\n'
}
# Keep execution last: a script downloaded through a pipe is parsed before prompts run.
main "$@"
