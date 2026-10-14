#!/usr/bin/env python3
"""Results of copies between two servers, written on the runner.

Every route writes ordinary results on the machine that ran syq. Through a
command-restricted receiver, the destination's own records of what it
changed arrive through the source, which cannot alter them; through other
routes, the coordinating server's records arrive. A refusal by the receiver
decides the outcome, and results the coordinator cuts short fail the copy.
"""
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = "/tmp/syq-real-ssh/results-stream"
FILES = ["a", "b", "sub/c"]


def run(argv, *, expected=0, env=None):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                            env=None if env is None else {**os.environ, **env})
    if result.returncode != expected:
        raise AssertionError(f"{shlex.join(argv)}: exit {result.returncode}, expected {expected}\n"
                             f"{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}")
    return result


def ssh(host, script):
    return run(["ssh", host, "python3 -c " + shlex.quote(script)])


def copy(name, *flags, expected=0, env=None, results=True):
    argv = ["syq", "cp", "--no-progress", "--performance-tuning", "workers=2",
            "--from", "source", "--srcs-in", ROOT + "/source",
            "--to", "destination", "--into", ROOT + "/" + name, *flags]
    with tempfile.TemporaryDirectory(prefix="syq-results-stream-") as temporary:
        path = Path(temporary) / "results.ndjson"
        result = run(argv + (["--results", str(path)] if results else []), expected=expected, env=env)
        records = [json.loads(line) for line in path.read_text().splitlines()] if results else []
    if records:
        # One ordinary stream, sequenced on this machine.
        assert records[0]["type"] == "run", records
        assert [record["seq"] for record in records] == list(range(len(records))), records
        assert records[-1]["type"] == "result", records
        assert not any("provenance" in record or record["type"] == "final_state" for record in records), records
    return result, records


def changed(records):
    return sorted(record["dst"]["value"] for record in records
                  if record["type"] == "operation_result" and record["action"] == "transfer_file"
                  and record["disposition"] == "succeeded")


def main():
    ssh("source", f"from pathlib import Path; p=Path({ROOT + '/source'!r}); (p/'sub').mkdir(parents=True); "
                  "[(p/name).write_bytes(name.encode()) for name in " + repr(FILES) + "]")
    ssh("destination", f"from pathlib import Path; Path({ROOT!r}).mkdir(parents=True)")

    print("results: restricted receiver, TCP and SSH data", flush=True)
    for name, flags in [("restricted", []), ("restricted-ssh", ["--no-tcp"])]:
        _, records = copy(name, *flags)
        assert changed(records) == FILES, (name, records)
        terminal = records[-1]
        assert terminal["status"] == "success" and terminal["exit_code"] == 0, terminal
        assert terminal["files_transferred"] == 3 and terminal["errors"] == 0, terminal

    print("results: unchanged totals come from the coordinator", flush=True)
    _, records = copy("restricted")
    assert changed(records) == [], records
    assert records[-1]["files_unchanged"] == 3 and records[-1]["files_transferred"] == 0, records[-1]

    print("results: a dry run through the restricted receiver", flush=True)
    _, records = copy("restricted-preview", "--dry-run")
    traced = sorted(record["dst"]["value"] for record in records
                    if record["type"] == "trace" and record["action"] == "transfer_file")
    assert traced == FILES, records
    assert records[-1]["dry_run"] and records[-1]["files_transferred"] == 3, records[-1]
    ssh("destination", f"from pathlib import Path; assert not Path({ROOT + '/restricted-preview/a'!r}).exists()")

    print("results: ordinary peer authentication at either end", flush=True)
    for name, flags in [("broker", ["--peer-auth", "broker"]),
                        ("destination-coordinator", ["--peer-auth", "broker", "--coordinate-at", "dst"])]:
        _, records = copy(name, *flags)
        assert changed(records) == FILES, (name, records)
        assert records[-1]["status"] == "success", records[-1]

    print("results: the receiver's refusals decide the outcome", flush=True)
    _, records = copy("refused", "--receiver-max-entries=2", expected=25)
    terminal = records[-1]
    assert terminal["status"] == "refused" and terminal["exit_code"] == 25, terminal
    assert any(record["type"] == "error" and record.get("class") == "safety_limit"
               and "refused" in record["message"] for record in records), records

    print("results: a stream the coordinator cuts short fails the copy", flush=True)
    cut = {"SYQ_TEST_DROP_DESTINATION_RESULTS_END": "1"}
    result, records = copy("cut", expected=1, env=cut)
    terminal = records[-1]
    assert terminal["status"] == "failed" and terminal["exit_code"] == 1, terminal
    assert any(record["type"] == "error" and record.get("class") == "integrity" for record in records), records
    assert b"could not be verified" in result.stderr, result.stderr
    # The check does not depend on --results.
    result, _ = copy("cut-quiet", expected=1, env=cut, results=False)
    assert b"could not be verified" in result.stderr, result.stderr
    print("Results stream checks passed", flush=True)


if __name__ == "__main__":
    main()
