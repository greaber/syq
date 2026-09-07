"""Mapping and timestamp selection across actual source/destination SSH edges."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def run(argv, *, data=None, expected=0):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode != expected:
        raise AssertionError(f"{shlex.join(argv)}: exit {result.returncode}\n{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}")
    return result


def ssh(host, script):
    return run(["ssh", host, "python3 -c " + shlex.quote(script)])


def manifest(entries):
    return "".join(json.dumps({"src": {"encoding": "utf-8", "value": src}, "dst": {"encoding": "utf-8", "value": dst}, "kind": kind}) + "\n" for src, dst, kind in entries).encode()


def direct():
    root = "/tmp/syq-real-ssh/mapping"
    source = root + "/source"
    ssh("destination", f"from pathlib import Path; Path({root!r}).mkdir(parents=True)")
    ssh("source", f"from pathlib import Path; import os; p=Path({source!r}); p.mkdir(parents=True); (p/'file').write_bytes(b'mapped contents'); (p/'directory').mkdir(); (p/'directory'/'unselected').write_bytes(b'exclude'); (p/'link').symlink_to('nested/renamed'); os.utime(p/'file',(1600000000,1600000000))")
    entries = [("file", "nested/renamed", "file"), ("link", "link", "symlink"), ("directory", "directory", "dir")]
    contents = manifest(entries)
    prefix = ["syq", "cp", "--no-progress", "-j", "2", "--from", "source", "-C", source]
    with tempfile.TemporaryDirectory(prefix="syq-mapping-") as temporary:
        path = Path(temporary) / "manifest.ndjson"
        path.write_bytes(contents)
        routes = [
            ("tcp", [], str(path)),
            ("ssh", ["--no-tcp"], "-"),
            ("fallback", ["--tcp-ports", f"{os.environ['SYQ_REAL_SSH_BLOCKED_TCP_PORT']}-{os.environ['SYQ_REAL_SSH_BLOCKED_TCP_PORT']}"], "-"),
            ("relay", ["--coordinate-at", "local"], "-"),
            ("destination-coordinator", ["--coordinate-at", "dst", "--peer-auth", "broker"], "-"),
        ]
        for name, flags, operand in routes:
            print(f"mapping route: {name}", flush=True)
            destination = root + "/" + name
            results_path = Path(temporary) / f"results-{name}.ndjson"
            result_flags = ["--results", str(results_path)] if name in {"tcp", "ssh", "fallback"} else []
            result = run(prefix + ["--mapping", operand, "--to", "destination", "--into", destination] + flags + result_flags, data=contents if operand == "-" else None)
            if result_flags:
                records = [json.loads(line) for line in results_path.read_text().splitlines()]
                assert records[-1]["type"] == "result" and records[-1]["status"] == "success", records[-1]
            if name == "fallback":
                assert b"data over ssh" in result.stderr, result.stderr
            ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'mapped contents'; assert (p/'link').is_symlink(); assert (p/'directory').is_dir(); assert not (p/'directory'/'unselected').exists()")
        destination = root + "/tcp"
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--verify-only"], data=contents)
        # Selection uses source mtimes; --only-existing remains independently enforced.
        ssh("destination", f"from pathlib import Path; import os; p=Path({destination!r})/'nested'/'renamed'; p.write_bytes(b'newer destination'); os.utime(p,(1700000000,1700000000))")
        updating = manifest([("file", "nested/renamed", "file"), ("file", "nested/missing", "file")])
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer", "--only-existing"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert not (p/'nested'/'missing').exists()")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert (p/'nested'/'missing').read_bytes()==b'mapped contents'")
        ssh("destination", f"import os; os.utime({destination + '/nested/renamed'!r},(1500000000,1500000000))")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer"], data=updating)
        ssh("destination", f"from pathlib import Path; assert Path({destination + '/nested/renamed'!r}).read_bytes()==b'mapped contents'")
        # Exceeds both the old grant scope count and one mapping protocol chunk.
        large = manifest([("file", f"group/file-{i}", "file") for i in range(10_000)])
        assert len(large) > 1024 * 1024
        print("mapping route: large SSH manifest", flush=True)
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", root + "/large", "--no-tcp"], data=large)
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large/group'!r}); files=list(p.iterdir()); assert len(files)==10000; assert all(f.read_bytes()==b'mapped contents' for f in files)")
    print("Restricted mapping and timestamp selection passed", flush=True)


def named():
    source = "/tmp/syq-real-ssh/return-source"
    contents = manifest([("message.txt", "nested/renamed", "file")])
    prefix = ["syq", "cp", "--no-progress", "-C", source, "--mapping", "-", "--to", "@laptop", "--into", "mapped-return"]
    run(prefix, data=contents)
    run(prefix + ["--verify-only"], data=contents)
    run(prefix + ["--skip-newer", "--only-existing"], data=contents)
    print("Named mapping and timestamp selection passed", flush=True)


if __name__ == "__main__":
    (named if sys.argv[1:] == ["named"] else direct)()
