#!/usr/bin/env python3
"""Test the command-reference generator and the documentation link checker."""
from support import ROOT

import importlib.util
from pathlib import Path
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli_reference = load("cli_reference", ROOT / "tests/cli_reference.py")
check_doc_links = load("check_doc_links", ROOT / "scripts/check-doc-links.py")


class CommandReference(unittest.TestCase):
    def test_wrapped_command_descriptions_are_read_whole(self):
        help_text = """Usage: syq persist [OPTIONS] <COMMAND>

Commands:
  on      Keep connections open
  off     Turn persistence off; a set made
          by on --ephemeral is deleted
  status  Advanced: Show readiness
  help    Print this message or the help of the given subcommand(s)

Options:
      --pscope <PATH>
          Use the isolated settings at PATH
"""
        _, groups, children = cli_reference.parse_help(help_text)
        self.assertEqual(children, [
            ("on", "Keep connections open"),
            ("off", "Turn persistence off; a set made by on --ephemeral is deleted"),
            ("status", "Show readiness"),
        ])
        self.assertEqual(groups, [("Options", [["--pscope <PATH>", ["Use the isolated settings at PATH"]]])])


class LinkChecker(unittest.TestCase):
    def test_included_headings_count_as_anchors(self):
        with tempfile.TemporaryDirectory(prefix="syq-doc-links.") as directory:
            root = Path(directory)
            (root / "sdk").mkdir()
            (root / "docs").mkdir()
            (root / "sdk/API.md").write_text(
                "## Outside\n<!-- ANCHOR: part -->\n## Inside\n<!-- ANCHOR_END: part -->\n")
            page = root / "docs/page.md"
            page.write_text("# Page\n\n{{#include ../sdk/API.md:part}}\n")
            anchors = check_doc_links.anchors(check_doc_links.expand_includes(page, page.read_text()))
            self.assertEqual(anchors, {"page", "inside"})


if __name__ == "__main__":
    unittest.main()
