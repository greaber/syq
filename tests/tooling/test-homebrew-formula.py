#!/usr/bin/env python3
"""Generate the formula in a path Homebrew recognizes as a tap and run its
native style/parser checks. Intended for the disposable macOS CI runner."""
from support import SCRIPTS

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest



class HomebrewFormulaTests(unittest.TestCase):
    def test_generated_formula_passes_brew_style(self):
        with tempfile.TemporaryDirectory(prefix="syq-homebrew-test.") as work:
            formula_dir = Path(work, "homebrew-tap/Formula")
            formula_dir.mkdir(parents=True)
            manifest = Path(work, "manifest.json")
            formula = formula_dir / "syq.rb"
            artifacts = {target: {"binary": {"name": f"syq-{target}", "sha256": digit * 64}}
                         for target, digit in [("linux-x86_64", "1"), ("linux-aarch64", "2"),
                                               ("macos-arm64", "3"), ("macos-x86_64", "4")]}
            manifest.write_text(json.dumps({
                "repository": "https://github.com/greaber/syq", "version": "0.1.0", "tag": "v0.1.0",
                "artifacts": artifacts}, indent=2, sort_keys=True) + "\n")
            subprocess.run([str(SCRIPTS / "generate-homebrew-formula.py"), str(manifest),
                            str(formula)], check=True)
            subprocess.run(["brew", "style", str(formula)], check=True,
                           env=dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1"))


if __name__ == "__main__":
    if not shutil.which("brew"):
        print("Homebrew formula tests need brew", file=sys.stderr)
        sys.exit(1)
    unittest.main()
