#!/usr/bin/env python3
"""Compare the shared UI toolkit in syq-bench and syq; no network or writes."""

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("bench", type=Path, help="syq-bench's src/syq_bench directory")
parser.add_argument("docs", type=Path, help="syq's theme directory")
args = parser.parse_args()
mapping = json.loads(Path(__file__).with_name("site-ui.json").read_text())
failures = []
count = 0
for source, target in mapping.items():
    left, right = args.bench / source, args.docs / target
    pairs = [(left, right)]
    if left.is_dir():
        names = {p.relative_to(left) for p in left.rglob("*") if p.is_file()}
        names |= {p.relative_to(right) for p in right.rglob("*") if p.is_file()}
        pairs = [(left / name, right / name) for name in sorted(names)]
    for left, right in pairs:
        count += 1
        if not left.is_file() or not right.is_file() or left.read_bytes() != right.read_bytes():
            failures.append(f"{left} differs from {right}")
if failures:
    print("\n".join(failures))
    raise SystemExit(1)
print(f"Shared UI toolkit matches ({count} files).")
