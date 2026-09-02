#!/usr/bin/env python3
"""Refuse a syq release while native options await Python SDK work."""

from __future__ import annotations

import json
from pathlib import Path


root = Path(__file__).resolve().parents[1]
inventory = json.loads((root / "sdk/python/native-api.json").read_bytes())
waiting = {
    command: (["<command>"] if values["sdk"] == "follow_up" else [])
    + values["follow_up"]
    for command, values in inventory["commands"].items()
    if values["sdk"] == "follow_up" or values["follow_up"]
}
if waiting:
    for command, options in waiting.items():
        labels = [option if option == "<command>" else "--" + option for option in options]
        print(f"syq {command}: Python SDK follow-up required for {', '.join(labels)}")
    raise SystemExit(1)
print("Python native API inventory has no pending follow-ups")
