"""Report all differing wheel members without rewriting the artifacts."""
from pathlib import Path
import difflib
import hashlib
import zipfile

root = Path("target/python-repro/results")
first = next((root / "first").glob("*.whl"))
second = next((root / "second").glob("*.whl"))
for path in (first, second):
    print(path.name, hashlib.sha256(path.read_bytes()).hexdigest())
with zipfile.ZipFile(first) as a, zipfile.ZipFile(second) as b:
    assert a.namelist() == b.namelist(), "Wheel members differ"
    for name in a.namelist():
        x, y = a.read(name), b.read(name)
        if x == y:
            continue
        print("Differing member:", name)
        if name.endswith((".json", "RECORD", "WHEEL", "METADATA")):
            print("\n".join(difflib.unified_diff(
                x.decode().splitlines(), y.decode().splitlines(),
                fromfile="first", tofile="second")))
        else:
            print("Lengths:", len(x), len(y))
            print("Different bytes:", sum(x != y for x, y in zip(x, y)))
            print("SHA256:", hashlib.sha256(x).hexdigest(), hashlib.sha256(y).hexdigest())
for suffix in ("*.whl", "*.tar.gz"):
    x = next((root / "first").glob(suffix))
    y = next((root / "second").glob(suffix))
    print(suffix, "byte-identical:", x.read_bytes() == y.read_bytes())
