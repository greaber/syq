#!/usr/bin/env python3
"""Check that comparison coverage cannot silently become a capability claim."""
from html.parser import HTMLParser
import json
from pathlib import Path
import unittest


class Examples(HTMLParser):
    def __init__(self):
        super().__init__()
        self.groups = {}
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "details" and "data-tool" in attrs:
            name = attrs["data-tool"]
            if name in self.groups:
                raise ValueError(f"duplicate tool: {name}")
            self.current = {"tasks": [], "unsupported": json.loads(attrs.get("data-unsupported", "{}"))}
            self.groups[name] = self.current
        if tag == "section" and attrs.get("class") == "tool-example":
            self.current["tasks"].append(attrs["data-title"])


class ComparisonCoverage(unittest.TestCase):
    def setUp(self):
        parser = Examples()
        path = Path(__file__).resolve().parent.parent / "docs/assets/tool-examples.html"
        parser.feed(path.read_text())
        self.groups = parser.groups

    def test_every_combination_is_an_example_or_an_explicit_limitation(self):
        self.assertEqual(set(self.groups), {"rsync", "rclone", "s5cmd", "scp", "syq"})
        titles = set().union(*(set(group["tasks"]) for group in self.groups.values()))
        for tool, group in self.groups.items():
            with self.subTest(tool=tool):
                tasks = set(group["tasks"])
                self.assertEqual(len(tasks), len(group["tasks"]), "duplicate task")
                unsupported = group["unsupported"]
                self.assertFalse(tasks & unsupported.keys())
                self.assertEqual(titles, tasks | unsupported.keys())
                self.assertTrue(all(isinstance(reason, str) and reason.strip()
                                    for reason in unsupported.values()))

    def test_supported_tasks_are_not_disabled(self):
        expected = {
            "rclone": {"Send a folder to a server", "Download a file from a server"},
            "s5cmd": {"Upload a folder’s contents to S3", "Match a folder, deleting extra files",
                      "Copy the files inside a folder"},
            "scp": {"Copy the files inside a folder"},
            "rsync": set(),
        }
        for tool, tasks in expected.items():
            with self.subTest(tool=tool):
                self.assertLessEqual(tasks | {"Choose destination names with a script"},
                                     set(self.groups[tool]["tasks"]))

    def test_workarounds_do_not_enable_a_different_task(self):
        exact_tasks = {
            "Send from a server shell to a laptop with no SSH server",
            "Copy directly between servers using only laptop logins",
        }
        self.assertLessEqual(exact_tasks, set(self.groups["syq"]["tasks"]))
        for tool in ("rsync", "rclone", "s5cmd", "scp"):
            with self.subTest(tool=tool):
                self.assertLessEqual(exact_tasks, self.groups[tool]["unsupported"].keys())
                self.assertFalse(exact_tasks & set(self.groups[tool]["tasks"]))


if __name__ == "__main__":
    unittest.main()
