"""Locate production tooling when a test is run directly."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
