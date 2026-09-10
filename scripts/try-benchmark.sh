#!/usr/bin/env bash
# Standalone Linux/macOS benchmark. Bash 3.2 compatible; no syq-bench install.
set -euo pipefail
export LC_ALL=C
# Quote remote paths ourselves for both old (including macOS) and new rsync.
export RSYNC_OLD_ARGS=1
export RSYNC_RSH="ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3"

usage() {
    cat <<'HELP'
Compare syq with rsync, and cp for local copies, using disposable synthetic data.

Usage: bash try-benchmark.sh [OPTIONS] [-- SYQ_OPTIONS...]
Without --yes, unanswered choices are prompted through /dev/tty (also with curl | bash).

  --mode local|push|pull    Copy locally, to an SSH host (default), or from one
  --host USER@HOST          SSH host or config alias (configure ports in ~/.ssh/config)
  --workload large|small|both
                           Small files by default; large tests are opt-in.
  --size auto|quick|medium|large
                           Quick (default): 64 MiB or 1,024 files; auto sizes with syq;
                           medium: 1 GiB + 4,096;
                           large: 8 GiB + 16,384. Small files are 8 KiB each.
  --source-dir DIR         Local scratch parent (default: current directory)
  --dest-dir DIR           Destination scratch parent (default: current directory)
                           For push/pull this is the REMOTE scratch parent.
                           For pull, --source-dir is the local destination parent.
  --tool all|syq|rsync|cp   Tools to time (default: all; cp requires local mode)
  --rounds N               Trials per tool/workload, rotating order (default: 3)
  --warmup on|off          Untimed syq tuning warm-up before each network workload
                           (default: on). Skip with manual tuning or other tools.
  --install                Install syq locally if missing, using its official installer
  --yes                    Use defaults for unspecified choices; do not prompt
  --help                   Show this help

After --, tune syq with --connections/-j, --tuning-options, --bwlimit,
--tcp-ports, --tcp-congestion (each takes a value), or --no-tcp, --no-compress,
--tcp-plain, --inplace, --stats, --no-progress, -v/-vv/--verbose.
These options also apply to syq setup/warm-up/calibration; rsync and cp are unchanged.
Add -v/-vv/--verbose after -- to show full commands and scratch paths.
Use --tool syq --rounds 1 --size quick for one scored syq copy per workload.
The untimed setup copy, eligible warm-up, and content checks still run. Source/destination,
removal and output-file options are not accepted after --.

Requires Bash, rsync, OpenSSL, and standard Unix utilities locally. Syq timing
uses Perl with its core JSON::PP module; terminal runs also need Perl. Remote tests
also need SSH locally and rsync plus standard utilities on the remote host.
SSH tests disable syq persistence in private settings and prevent rsync from
reusing SSH connections. Every timed trial includes connection startup.
Auto-tuning and remembered counts stay active unless overridden by tuning options.
Warm-up aims for 60 copying seconds, using up to four growing copies of at most
1 GiB each, space permitting. This is not a wall-time limit or proof tuning settled.
Pull warm-ups generate matching source data remotely (needs Bash and OpenSSL).
Use --warmup off for a short comparison using the existing cached/default count.
Syq also reports copying time, copying MB/s, and other time (setup/finish).
A note flags >=20% outside copying or copying under one second: total-time
speeds may not show sustained throughput.
The default push needs --host with --yes. Use a second machine, preferably
on a fast link with some latency and reachable TCP data ports 47600-47699.
Local results report seconds: filesystem clones do not measure byte throughput.
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
remote() { ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 "$host" "$1"; }

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
# Fixed-size argument batches avoid both one process per file and ARG_MAX.
# The same POSIX shell program runs at both ends; LC_ALL=C fixes glob order.
# shellcheck disable=SC2016 # This is a literal program for bash -c on each host.
manifest_command='set -eu
export LC_ALL=C
root=$1
shift
for file in "$root"/*; do
    set -- "$@" "$file"
    if [ "$#" -eq 128 ]; then cksum "$@" || exit; set --; fi
done
if [ "$#" -gt 0 ]; then cksum "$@"; fi'
# Generated filenames have no whitespace. Strip the parent from cksum output
# after checking its exit status through pipefail; never enter the scratch tree.
manifest_names() { sed 's@ /.*\(/[^/]*\)$@ \1@'; }
manifest() { bash -c "$manifest_command" manifest "$1" | manifest_names; }
remote_manifest() { remote "set -- $(quote "$1")
$manifest_command" | manifest_names; }

data_command() {
    local workload=$1 amount=$2 root=$3 block=8192
    # Fixed AES-CTR stream: deterministic, dense and effectively incompressible.
    # One generator for local and remote data. Paths are quoted, and the program
    # stays on one line for transport through the remote shell.
    [[ $workload != large ]] || block=1048576
    printf 'set -euo pipefail; mkdir %s; dd if=/dev/zero bs=%s count=%s 2>/dev/null | openssl enc -aes-256-ctr -nosalt -K %s -iv %s' \
        "$(quote "$root/$workload")" "$block" "$amount" "$key" "$iv"
    if [[ $workload == large ]]; then
        printf ' > %s\n' "$(quote "$root/$workload/data")"
    else
        printf ' | split -b 8192 -a 6 - %s\n' "$(quote "$root/$workload/file-")"
    fi
}
make_data() { bash -c "$(data_command "$1" "$2" "$local_root")"; }
prepare_dataset() {
    local workload=$1 amount=$2
    if [[ $workload == large ]]; then
        printf 'Generating one %s MiB file...\n' "$amount"
        bytes=$((amount * 1048576))
    else
        printf 'Generating %s files of 8 KiB each...\n' "$amount"
        bytes=$((amount * 8192))
    fi
    run make_data "$workload" "$amount"
    printf 'Preparing content checks...\n'
    manifest "$local_root/$workload" > "$local_root/expected"
    source=$local_root/$workload
    if [[ $mode == pull ]]; then
        if [[ ${3:-} == warmup ]]; then
            # Avoid uploading a large tuning fixture over the laptop uplink
            # before testing its downlink. Generate the identical byte stream.
            printf 'Generating matching remote warm-up data (untimed)...\n'
            run remote "bash -c $(quote "$(data_command "$workload" "$amount" "$remote_root")")"
        else
            printf 'Staging source on remote host (untimed)...\n'
            run rsync -rpt -- "$source/" "$host:$(quote "$remote_root/$workload/")"
        fi
        source=$remote_root/$workload
        remote_manifest "$source" > "$local_root/actual"
        cmp "$local_root/expected" "$local_root/actual" || fail 'Remote staging verification failed.'
    fi
}

warm_up() {
    local workload=$1 amount capacity next copying_ms attempt limit
    if [[ $workload == large ]]; then amount=64; limit=1024
    else amount=1024; limit=131072; fi
    if [[ ${SYQ_BENCHMARK_TEST_SMALL_FIXTURES:-} == 1 ]]; then
        if [[ $workload == large ]]; then amount=1; limit=4
        else amount=8; limit=32; fi
    fi
    capacity=$(space_capacity "$workload")
    [[ $capacity -le $limit ]] || capacity=$limit
    if [[ $capacity -lt 1 ]]; then
        printf 'Note: no room for the %s warm-up; using existing cached/default tuning.\n' "$workload"
        return
    fi
    [[ $amount -le $capacity ]] || amount=$capacity
    printf '\nWarming up syq for %s (untimed; target 60 copying seconds, up to 4 copies, 1 GiB per dataset)...\n' "$workload"
    for ((attempt=1; attempt<=4; attempt++)); do
        prepare_dataset "$workload" "$amount" warmup
        destination=$dest_root/warmup
        if [[ $mode == push ]]; then destination=$remote_root/warmup; remote "mkdir $(quote "$destination")"
        else mkdir "$destination"; fi
        rm -f -- "$local_root/warmup.json"
        run copy_with syq "$source" "$destination" warmup || fail 'Syq warm-up failed.'
        if [[ $mode == push ]]; then remote_manifest "$destination" > "$local_root/actual"
        else manifest "$destination" > "$local_root/actual"; fi
        cmp "$local_root/expected" "$local_root/actual" || fail 'Warm-up content check failed.'
        copying_ms=$(copying_interval "$local_root/warmup.json") || fail 'Cannot read syq warm-up timing.'
        if [[ $mode == push ]]; then remote "rm -rf $(quote "$destination")"
        else rm -rf -- "$destination"; fi
        # Check space before removing the source, as for automatic sizing.
        capacity=$(space_capacity "$workload")
        [[ $capacity -le $limit ]] || capacity=$limit
        rm -rf -- "${local_root:?}/${workload:?}"
        [[ $mode != pull ]] || remote "rm -rf $(quote "$source")"
        if [[ $copying_ms == n/a ]]; then
            printf 'Note: warm-up verified, but this syq cannot report copying time; tuning may not have settled.\n'
            return
        fi
        awk -v ms="$copying_ms" 'BEGIN {printf "Verified warm-up; copying interval %.3f seconds.\n", ms/1000}'
        [[ $copying_ms -lt 60000 ]] || return 0
        next=$(next_amount "$amount" "$copying_ms" "$capacity" 60000)
        [[ $next -gt $amount && $attempt -lt 4 ]] || break
        amount=$next
    done
    printf 'Note: %s warm-up reached its size, space or attempt limit before 60 copying seconds; tuning may not have settled.\n' "$workload"
}

copy_with() {
    local tool=$1 source=$2 destination=$3
    local command=() syq_options=(--preserve=permissions --results "$local_root/trial.json")
    $show_syq_summary || syq_options+=(--suppress-summary)
    # Always suppress the tiny setup copy's summary, keeping bootstrap
    # diagnostics and authentication prompts live. Supported
    # by the released v0.3.2 CLI as well as current builds.
    [[ ${4:-} != setup ]] || syq_options=(--preserve=permissions --suppress-summary --no-progress)
    [[ ${4:-} != calibration ]] || syq_options=(--preserve=permissions --suppress-summary --results "$local_root/calibration.json")
    [[ ${4:-} != warmup ]] || syq_options=(--preserve=permissions --suppress-summary --results "$local_root/warmup.json")
    if $has_syq_options; then syq_options+=("${syq_extra[@]}"); fi
    case $tool in
        syq)
            case $mode in
                local) command=(syq cp "${syq_options[@]}" --srcs-in "$source" --into-existing "$destination") ;;
                push) command=(syq cp "${syq_options[@]}" --srcs-in "$source" --to "$host" --into-existing "$destination") ;;
                pull) command=(syq cp "${syq_options[@]}" --from "$host" --srcs-in "$source" --into-existing "$destination") ;;
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
    if $verbose; then copy_with "$@" show; fi
    TIMEFORMAT='%R'
    { time copy_with "$@" 1>&4 2>&5; } 2> "$local_root/time"
}

# Allow two copies on each filesystem and leave 10% free. For small files,
# allow extra allocation for metadata. Rechecking with the current source still
# present is conservative: it may stop growth slightly before the disk limit.
space_capacity() {
    local workload=$1 local_free destination_free unit
    local_free=$(df -Pk "$local_root" | available_kib) || fail 'Cannot determine local free space.'
    if [[ $mode == local ]]; then
        destination_free=$(df -Pk "$dest_root" | available_kib) || fail 'Cannot determine destination free space.'
    else
        destination_free=$(remote "df -Pk $(quote "$remote_root")" | available_kib) || fail 'Cannot determine remote free space.'
    fi
    if [[ $workload == large ]]; then unit=1024; else unit=16; fi
    awk -v a="$local_free" -v b="$destination_free" -v unit="$unit" \
        'BEGIN {free=(a < b ? a : b); printf "%.0f\n", int(free * 0.45 / unit)}'
}
available_kib() {
    awk 'NR > 1 && $4 ~ /^[0-9]+$/ {available=$4; found=1}
         END {if (!found) exit 1; print available}'
}
next_amount() {
    awk -v current="$1" -v ms="$2" -v capacity="$3" -v target="${4:-5000}" 'BEGIN {
        estimate=current * target / (ms > 0 ? ms : 1);
        amount=int(estimate); if (amount < estimate) amount++;
        minimum=int(current * 1.25); if (minimum < current * 1.25) minimum++;
        if (amount < minimum) amount=minimum;
        if (amount > current*10) amount=current*10;
        if (amount > capacity) amount=capacity;
        printf "%.0f\n", amount;
    }'
}
calibration_interval() {
    copying_interval "$1" required
}
copying_interval() {
    perl -MJSON::PP -e '
        my $required=shift @ARGV;
        my $result;
        while (<>) {
            my $record=decode_json($_);
            $result=$record if ($record->{type} // "") eq "result";
        }
        die "Missing successful result\n" unless
            $result && ($result->{status} // "") eq "success";
        if (!defined($result->{copying_elapsed_ms}) && $required ne "required") {
            print "n/a\n"; exit;
        }
        die "Missing or invalid copying timing\n" unless
            defined($result->{copying_elapsed_ms}) && $result->{copying_elapsed_ms} =~ /^\d+$/;
        print $result->{copying_elapsed_ms}, "\n";
    ' "${2:-optional}" "$1"
}

summarize_syq_timings() {
    [[ -s $1 ]] || return 0
    printf '\nSyq timing breakdown (means per trial):\n'
    awk '{
        key=$1; if (!(key in n)) order[++count]=key;
        n[key]++; total[key]+=$2;
        if ($3 == "n/a") unavailable[key]=1;
        else {
            copying[key]+=$3 / 1000;
            if ($3 > 0) speed[key]+=$4 / $3 / 1000;
            else unmeasurable[key]=1;
        }
    } END {
        printf "%-18s %10s %10s %10s %12s\n", "Workload", "Total s", "Copying s", "Other s", "Copy MB/s";
        for (i=1; i<=count; i++) {
            key=order[i];
            if (unavailable[key]) {
                printf "%-18s %10.3f %10s %10s %12s\n", key, total[key]/n[key], "n/a", "n/a", "n/a";
                print "Note (" key "): copying timing unavailable; update syq for a breakdown.";
                continue;
            }
            other=total[key]-copying[key];
            printf "%-18s %10.3f %10.3f %10.3f %12s\n", key, total[key]/n[key], copying[key]/n[key], other/n[key], (unmeasurable[key] ? "n/a" : sprintf("%.3f", speed[key]/n[key]));
            if (unmeasurable[key])
                print "Note (" key "): copying speed unavailable; a copying interval was below timer resolution (0.001 s).";
            if (total[key] > 0 && other >= total[key]*0.2) {
                printf "Note (%s): %.0f%% of syq total time was outside copying; setup/finish substantially affects this comparison.\n", key, other/total[key]*100;
                short_test=1;
            }
            if (copying[key]/n[key] < 1) {
                print "Note (" key "): syq copying averaged under 1 second; this test is too short to assess sustained throughput.";
                short_test=1;
            }
        }
        if (short_test) print "For longer tests, use --workload large --size auto or a larger fixed --size.";
    }' "$1"
    printf 'Other = time outside copying (setup/finish). Copying includes waiting and can overlap setup; it is not pure network time.\n'
    printf 'Copy MB/s uses copying time; compare tools using total-time results above.\n'
}

summarize_results() {
    awk -v metric="${2:-speed}" '{key=$1 " " $2;
          if (!(key in n)) order[++count]=key;
          n[key]++;
          if ($3 <= 0) {unmeasurable[key]=1; next}
          speed=(metric == "seconds" ? $3 : $4 / $3 / 1000000);
          if (!(key in total)) {low[key]=speed; high[key]=speed}
          total[key]+=speed;
          if (speed < low[key]) low[key]=speed; if (speed > high[key]) high[key]=speed}
         END {printf "%-18s %10s %10s %10s %8s\n", "Workload / tool", "Mean", "Min", "Max", "Trials";
              for (i=1; i<=count; i++) {
                  key=order[i];
                  if (unmeasurable[key]) {
                      printf "%-18s %10s %10s %10s %8d\n", key, "n/a", "n/a", "n/a", n[key];
                      note=1;
                  } else printf "%-18s %10.3f %10.3f %10.3f %8d\n", key, total[key]/n[key], low[key], high[key], n[key];
              }
              if (note) print "n/a: a copy finished below timer resolution (0.001 s); elapsed time is <0.001 s. Try a larger test.";
         }' "$1"
}

main() {
    local mode='' workload='' size='' source_dir='' dest_dir='' rounds=3 yes=false install=false
    local option tool round index offset source destination case_name bytes seconds speed local_parent remote_parent
    local large_mib small_files syq_identity selected_tool=all has_syq_options=false verbose=false show_syq_summary=false
    local warmup=on warmup_enabled=false manual_tuning=false
    local syq_extra=()
    local key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    local iv=000102030405060708090a0b0c0d0e0f
    while [[ $# -gt 0 ]]; do
        option=$1
        case $option in
            --help|-h) usage; return ;;
            --yes) yes=true; shift; continue ;;
            --install) install=true; shift; continue ;;
            --)
                shift
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        --connections|-j|--tuning-options|--bwlimit|--tcp-ports|--tcp-congestion)
                            [[ $# -ge 2 && -n $2 ]] || fail "$1 needs a value"
                            case $1 in --connections|-j|--tuning-options) manual_tuning=true ;; esac
                            syq_extra+=("$1" "$2"); shift 2 ;;
                        --connections=?*|--tuning-options=?*|--bwlimit=?*|--tcp-ports=?*|--tcp-congestion=?*|-j[0-9]*)
                            case $1 in --connections=*|--tuning-options=*|-j[0-9]*) manual_tuning=true ;; esac
                            syq_extra+=("$1"); shift ;;
                        -v|-vv|--verbose)
                            verbose=true; show_syq_summary=true; syq_extra+=("$1"); shift ;;
                        --stats)
                            show_syq_summary=true; syq_extra+=("$1"); shift ;;
                        --no-tcp|--no-compress|--tcp-plain|--inplace|--no-progress)
                            syq_extra+=("$1"); shift ;;
                        *) fail "Unsupported syq benchmark option: $1 (see --help for tuning options)" ;;
                    esac
                    has_syq_options=true
                done
                break ;;
            --mode|--host|--workload|--size|--source-dir|--dest-dir|--rounds|--tool|--warmup)
                [[ $# -ge 2 && -n $2 ]] || fail "$option needs a value"
                case $option in
                    --mode) mode=$2 ;; --host) host=$2 ;; --workload) workload=$2 ;;
                    --size) size=$2 ;; --source-dir) source_dir=$2 ;; --dest-dir) dest_dir=$2 ;;
                    --rounds) rounds=$2 ;; --tool) selected_tool=$2 ;; --warmup) warmup=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $option (see --help)" ;;
        esac
    done
    [[ -z $host || -n $mode ]] || mode=push
    if { exec 3</dev/tty; } 2>/dev/null; then
        : # Also allow SSH credential prompts when --yes supplies benchmark choices.
    elif ! $yes; then
        fail 'No terminal. Pass --yes and your choices (see --help).'
    fi
    if ! $yes; then
        if [[ -z $mode ]]; then ask 'Copy where? push / pull / local' push; mode=$REPLY; fi
        if [[ $mode != local && -z $host ]]; then ask 'SSH host or config alias' ''; host=$REPLY; fi
        if [[ -z $workload ]]; then ask 'Workloads? small / large / both' small; workload=$REPLY; fi
        if [[ -z $source_dir ]]; then ask 'Local scratch parent' "$PWD"; source_dir=$REPLY; fi
        if [[ -z $dest_dir ]]; then
            if [[ $mode == local ]]; then ask 'Destination scratch parent (can be another disk or NFS mount)' "$source_dir"
            else ask 'Remote scratch parent (existing writable directory)' .; fi
            dest_dir=$REPLY
        fi
    fi
    mode=${mode:-push}; workload=${workload:-small}; size=${size:-quick}
    source_dir=${source_dir:-$PWD}; dest_dir=${dest_dir:-.}
    case $mode in local|push|pull) ;; *) fail 'Mode must be local, push or pull.' ;; esac
    case $selected_tool in all|syq|rsync|cp) ;; *) fail 'Tool must be all, syq, rsync or cp.' ;; esac
    [[ $selected_tool != cp || $mode == local ]] || fail 'cp requires --mode local.'
    if $has_syq_options && [[ $selected_tool != all && $selected_tool != syq ]]; then
        fail 'Syq tuning options require --tool syq or --tool all.'
    fi
    case $workload in large|small|both) ;; *) fail 'Workload must be large, small or both.' ;; esac
    case $warmup in on|off) ;; *) fail 'Warmup must be on or off.' ;; esac
    if [[ $warmup == on && $mode != local && ( $selected_tool == all || $selected_tool == syq ) ]] && ! $manual_tuning; then
        warmup_enabled=true
    fi
    case $size in auto|quick) large_mib=64; small_files=1024 ;; medium) large_mib=1024; small_files=4096 ;; large) large_mib=8192; small_files=16384 ;; *) fail 'Size must be auto, quick, medium or large.' ;; esac
    # The script tests exercise real generation, copies, checksums, ordering,
    # and cleanup. Smaller private fixtures keep that coverage without making
    # prompt-routing tests copy the full user-facing benchmark workload.
    if [[ ${SYQ_BENCHMARK_TEST_SMALL_FIXTURES:-} == 1 ]]; then
        large_mib=1
        small_files=8
    fi
    [[ $rounds =~ ^[1-9]$ ]] || fail 'Rounds must be between 1 and 9.'
    for tool in bash rsync openssl dd split cksum cmp awk mktemp mkdir rm cat ps sleep sed; do need "$tool"; done
    [[ $mode != local ]] || need cp
    if [[ $size == auto ]] || $warmup_enabled; then need df; fi
    if [[ $size == auto || $selected_tool == all || $selected_tool == syq ]]; then
        need perl
        perl -MJSON::PP -e 1 || fail 'Syq timing needs Perl with JSON::PP.'
    fi
    if [[ $mode != local ]]; then
        [[ -n $host ]] || fail 'Network benchmarks need an SSH host. Pass --host USER@HOST, or --mode local for a local comparison.'
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
    # Isolate both policy and runtime before disabling persistence. A private
    # config alone would still make persist off close the user's global scope.
    # Keep the normal helper cache: installation is prepared outside the timer.
    mkdir -m 700 "$local_root/config" "$local_root/runtime"
    export XDG_CONFIG_HOME="$local_root/config"
    export XDG_RUNTIME_DIR="$local_root/runtime"
    run syq persist off || fail 'Could not disable syq persistence for this benchmark.'
    printf '\nVersions:\n'
    syq_identity=$(syq --build-identity)
    printf 'syq: %s\n' "$syq_identity"
    rsync --version | sed -n '1p'
    if [[ $mode == local ]]; then
        dest_dir=$(cd -- "$dest_dir" && pwd -P) || fail 'Destination scratch parent must exist.'
        dest_root=$(mktemp -d "$dest_dir/syq-bench.XXXXXXXX")
    else
        printf '\nChecking SSH access and remote tools (normal SSH authentication applies)...\n'
        remote 'command -v rsync >/dev/null && command -v cksum >/dev/null && command -v mktemp >/dev/null && rsync --version' | sed -n '1p' || fail 'Remote needs rsync, cksum and mktemp, and working SSH access.'
        if $warmup_enabled && [[ $mode == pull ]]; then
            remote 'command -v bash >/dev/null && command -v openssl >/dev/null && command -v dd >/dev/null && command -v split >/dev/null' ||
                fail 'Pull warm-up needs Bash, OpenSSL, dd and split remotely; install them or use --warmup off.'
        fi
        [[ $dest_dir == /* ]] || dest_dir=./$dest_dir
        remote_parent=$(remote "cd $(quote "$dest_dir") && pwd -P")
        [[ $remote_parent == /* && $remote_parent != *$'\n'* ]] || fail 'Remote shell must print only the requested output.'
        remote_root=$(remote "mktemp -d $(quote "$remote_parent/syq-bench.XXXXXXXX")")
        [[ $remote_root == "$remote_parent/"syq-bench.* && $remote_root != *$'\n'* ]] || fail 'Unexpected remote scratch path.'
        dest_root=$(mktemp -d "$local_parent/syq-bench.XXXXXXXX")
    fi
    printf '\nMode: %s; workloads: %s; size: %s; rounds: %s\n' "$mode" "$workload" "$size" "$rounds"
    [[ $mode == local ]] || printf 'SSH host: %s\n' "$host"
    if $verbose; then
        printf 'Local scratch: %s\n' "$local_root"
        if [[ $mode == local ]]; then printf 'Destination scratch: %s\n' "$dest_root"
        else printf 'Remote scratch: %s\n' "$remote_root"; fi
    fi
    exec 4>&1 5>&2
    local tools=(syq rsync) workloads=(large small)
    [[ $mode != local ]] || tools+=(cp)
    [[ $selected_tool == all ]] || tools=("$selected_tool")
    [[ $workload == both ]] || workloads=("$workload")
    : > "$local_root/results"
    : > "$local_root/syq-timings"
    for case_name in "${workloads[@]}"; do
        if [[ $case_name == "${workloads[0]}" ]]; then
            # Do this once, not once per workload. Keep the measured copy's full
            # transport path, but suppress meaningless throughput for the 14-byte probe.
            if [[ $mode != local ]]; then
                printf 'Preparing syq %s on %s to match this machine (untimed)...\n' "$syq_identity" "$host"
            else
                printf 'Preparing the benchmark (untimed)...\n'
            fi
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
            if [[ $mode != local ]]; then
                printf 'Setup complete: syq %s is ready on %s.\n' "$syq_identity" "$host"
            else
                printf 'Setup complete.\n'
            fi
        fi
        local amount capacity next copying_ms
        if $warmup_enabled; then warm_up "$case_name"; fi
        if [[ $case_name == large ]]; then amount=$large_mib; else amount=$small_files; fi
        if [[ $size == auto ]]; then
            capacity=$(space_capacity "$case_name")
            [[ $capacity -ge 1 ]] || fail 'Not enough scratch space for a test dataset.'
            [[ $amount -le $capacity ]] || amount=$capacity
            printf '\nChoosing the %s workload size with syq (aiming for 5 seconds of copying)...\n' "$case_name"
        fi
        while :; do
            prepare_dataset "$case_name" "$amount"
            [[ $size == auto ]] || break
            destination=$dest_root/calibration
            if [[ $mode == push ]]; then destination=$remote_root/calibration; remote "mkdir $(quote "$destination")"
            else mkdir "$destination"; fi
            rm -f -- "$local_root/calibration.json"
            run copy_with syq "$source" "$destination" calibration || fail 'syq sizing copy failed.'
            printf 'Checking copied data...\n'
            if [[ $mode == push ]]; then remote_manifest "$destination" > "$local_root/actual"
            else manifest "$destination" > "$local_root/actual"; fi
            cmp "$local_root/expected" "$local_root/actual" || fail 'Sizing copy content check failed.'
            copying_ms=$(calibration_interval "$local_root/calibration.json") ||
                fail 'Automatic sizing needs syq with copying-interval timing. Update syq, or use --size quick for a fixed-size comparison.'
            if [[ $mode == push ]]; then remote "rm -rf $(quote "$destination")"
            else rm -rf -- "$destination"; fi
            awk -v ms="$copying_ms" 'BEGIN {printf "Verified sizing copy; copying interval %.3f seconds.\n", ms / 1000}'
            [[ $copying_ms -lt 5000 ]] || break
            capacity=$(space_capacity "$case_name")
            next=$(next_amount "$amount" "$copying_ms" "$capacity")
            if [[ $next -le $amount ]]; then
                printf 'WARNING: available scratch space limits test size. Short copies may mostly measure startup; interpret speeds cautiously.\n' >&2
                break
            fi
            rm -rf -- "${local_root:?}/${case_name:?}"
            [[ $mode != pull ]] || remote "rm -rf $(quote "$source")"
            amount=$next
            printf 'Increasing the dataset automatically...\n'
        done
        printf '%s: %s bytes per trial, %s tools × %s rounds.\n' "$case_name" "$bytes" "${#tools[@]}" "$rounds"
        for ((round=1; round<=rounds; round++)); do
            for ((offset=0; offset<${#tools[@]}; offset++)); do
                index=$(((round - 1 + offset) % ${#tools[@]}))
                tool=${tools[$index]}
                destination=$dest_root/trial
                if [[ $mode == push ]]; then destination=$remote_root/trial; remote "mkdir $(quote "$destination")"
                else mkdir "$destination"; fi
                printf '\n%s: %s, trial %s/%s (%s bytes)\n' "$case_name" "$tool" "$round" "$rounds" "$bytes"
                rm -f -- "$local_root/trial.json"
                run timed_copy "$tool" "$source" "$destination" || fail "$tool failed; no successful result recorded for this trial."
                seconds=$(cat "$local_root/time")
                if [[ $mode == push ]]; then remote_manifest "$destination" > "$local_root/actual"
                else manifest "$destination" > "$local_root/actual"; fi
                cmp "$local_root/expected" "$local_root/actual" || fail "$tool destination content check failed."
                printf '%s %s %s %s\n' "$case_name" "$tool" "$seconds" "$bytes" >> "$local_root/results"
                speed=$(awk -v bytes="$bytes" -v seconds="$seconds" 'BEGIN {
                    if (seconds > 0) printf "%.3f", bytes / seconds / 1000000;
                    else printf "n/a";
                }')
                if [[ $mode == local ]]; then
                    printf 'Verified contents; elapsed %s seconds.\n' "$seconds"
                else
                    printf 'Verified contents; speed %s MB/s; elapsed %s seconds.\n' "$speed" "$seconds"
                fi
                if [[ $tool == syq ]]; then
                    copying_ms=$(copying_interval "$local_root/trial.json") || fail 'Cannot read syq trial timing.'
                    if [[ $copying_ms != n/a ]]; then
                        awk -v ms="$copying_ms" -v seconds="$seconds" -v bytes="$bytes" 'BEGIN {
                            if (ms / 1000 > seconds) exit 1;
                            printf "Copying: %.3f s, %s MB/s; other: %.3f s.\n", ms/1000, (ms > 0 ? sprintf("%.3f", bytes/ms/1000) : "n/a"), seconds-ms/1000;
                        }' || fail 'Syq copying interval exceeds total trial time.'
                    fi
                    printf '%s %s %s %s\n' "$case_name" "$seconds" "$copying_ms" "$bytes" >> "$local_root/syq-timings"
                fi
                if [[ $mode == push ]]; then remote "rm -rf $(quote "$destination")"
                else rm -rf -- "$destination"; fi
            done
        done
        rm -rf -- "${local_root:?}/$case_name"
        [[ $mode != pull ]] || remote "rm -rf $(quote "$source") $(quote "$remote_root/probe")"
    done
    local metric=speed
    if [[ $mode == local ]]; then
        metric=seconds
        printf '\nResults (seconds; lower is faster; all copies checked):\n'
        printf 'Filesystem cloning may avoid moving file data; these are copy times, not disk bandwidth.\n'
    else
        printf '\nResults (MB/s; higher is faster; all copies checked):\n'
    fi
    [[ $mode == local ]] || printf 'Connection profile: syq persistence OFF; rsync fresh SSH; connection startup is timed for every trial.\n'
    summarize_results "$local_root/results" "$metric"
    summarize_syq_timings "$local_root/syq-timings"
}
# Keep execution last: a script downloaded through a pipe is parsed before prompts run.
main "$@"
