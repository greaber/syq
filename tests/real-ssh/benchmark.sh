#!/bin/sh
# Sourced after the disposable lab SSH setup in scenarios.sh.

# Exercise the user-facing script against real remote rsync and syq helpers.
# Quoted scratch names must survive both SSH and rsync's remote argument parsing.
benchmark_parent="$home/benchmark scratch's"
mkdir "$benchmark_parent"
ssh destination "mkdir -p \"/tmp/benchmark scratch's\""
for benchmark_mode in push pull; do
    bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload both --size quick --warmup off \
        --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's"
done
# Automatic sizing uses the real terminal timing from each remote direction.
for benchmark_mode in push pull; do
    bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload small --size auto --warmup off \
        --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's"
done
# One scored syq copy with transport and batch overrides in each direction.
for benchmark_mode in push pull; do
    bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload small --size quick \
        --tool syq --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's" \
        -- --no-tcp --performance-tuning workers=2 --performance-tuning batch-files=256,batch-bytes=2M
done
# A new route can learn during warm-up before the first scored copy. Speed up
# only the debug tuner's sample clock and cap traffic to keep this lab bounded.
# These are correctness checks, not performance measurements.
for benchmark_mode in push pull; do
    benchmark_cache="$home/benchmark-tuning-$benchmark_mode.json"
    SYQ_TUNING_CACHE="$benchmark_cache" SYQ_TEST_TUNE_SAMPLE_MS=100 \
        bash /usr/local/libexec/syq-try-benchmark --yes \
        --mode "$benchmark_mode" --host destination --workload small --size quick \
        --tool syq --rounds 1 --source-dir "$benchmark_parent" --dest-dir "/tmp/benchmark scratch's" \
        -- --no-tcp --resource-limits bandwidth=2M
    python3 - "$benchmark_cache" "$benchmark_mode" <<'PY'
import json, pathlib, sys
cache = json.loads(pathlib.Path(sys.argv[1]).read_text())
key = 'local>destination|ssh' if sys.argv[2] == 'push' else 'destination>local|ssh'
assert cache['paths'][key] >= 1, cache
print('Verified a learned starting count for', key)
PY
    rm -f "$benchmark_cache" "$benchmark_cache.lock"
done
test -z "$(find "$benchmark_parent" -mindepth 1 -print)"
ssh destination 'test -z "$(find "/tmp/benchmark scratch'"'"'s" -mindepth 1 -print)"'
rmdir "$benchmark_parent"
ssh destination "rmdir \"/tmp/benchmark scratch's\""
echo 'interactive benchmark push/pull passed'

# Interrupt a real copy after the remote partial file appears, then require all
# temporary data to be gone. An unrelated file in the scratch parent must stay.
# Keep the copy alive long enough for the one-second partial-file poll to see it.
cancel_parent=$home/benchmark-cancel
mkdir "$cancel_parent"
ssh destination 'mkdir /tmp/benchmark-cancel; printf keep > /tmp/benchmark-cancel/keep'
bash /usr/local/libexec/syq-try-benchmark --yes --mode push --host destination \
    --workload large --size quick --warmup off --rounds 1 --source-dir "$cancel_parent" \
    --dest-dir /tmp/benchmark-cancel -- --resource-limits bandwidth=1M &
benchmark_pid=$!
attempt=0
copy_started=false
while [ "$attempt" -lt 30 ]; do
    if ssh destination 'for file in /tmp/benchmark-cancel/syq-bench.*/trial/.data.syq-tmp.*; do
        if [ -f "$file" ]; then exit 0; fi
    done; exit 1'; then
        copy_started=true
        break
    fi
    if [ $((attempt % 5)) -eq 0 ]; then
        printf 'Waiting for remote benchmark partial file (%ss of 30s)...\n' "$attempt"
    fi
    sleep 1
    attempt=$((attempt + 1))
done
kill -TERM "$benchmark_pid" 2>/dev/null || true
benchmark_status=0
wait "$benchmark_pid" || benchmark_status=$?
if [ "$copy_started" != true ]; then
    echo 'benchmark cancellation timed out after 30s: no remote partial file observed' >&2
    exit 1
fi
test "$benchmark_status" -eq 143
test -z "$(find "$cancel_parent" -mindepth 1 -print)"
ssh destination 'test "$(cat /tmp/benchmark-cancel/keep)" = keep &&
    test "$(find /tmp/benchmark-cancel -mindepth 1 -maxdepth 1 | wc -l)" -eq 1'
rmdir "$cancel_parent"
ssh destination 'rm /tmp/benchmark-cancel/keep; rmdir /tmp/benchmark-cancel'
echo 'interactive benchmark remote interruption cleanup passed'
