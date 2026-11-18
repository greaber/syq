#!/usr/bin/env python3
"""Each real-SSH case can run without the others' shell functions."""
from support import ROOT, SCRIPTS

import importlib.util
import re
import unittest

spec = importlib.util.spec_from_file_location("real_ssh", SCRIPTS / "test-real-ssh.py")
real_ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real_ssh)

DEFINITION = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", re.MULTILINE)


def functions_used_elsewhere(text):
    """Return (function, defining case, using part) for cross-case calls."""
    setup, cases, final = real_ssh.scenario_parts(text)
    parts = [(name, "".join(lines)) for name, lines in cases]
    parts.append(("final checks", "".join(final)))
    defined = {name: set(DEFINITION.findall(body)) for name, body in parts}
    shared = set(DEFINITION.findall("".join(setup)))
    problems = []
    for owner, functions in defined.items():
        for function in sorted(functions - shared):
            word = re.compile(rf"(?<![\w-]){re.escape(function)}(?![\w-])")
            for user, body in parts:
                if user != owner and function not in defined[user] and word.search(body):
                    problems.append((function, owner, user))
    return problems


class ScenarioFunctionTests(unittest.TestCase):
    def test_cases_call_only_setup_functions_or_their_own(self):
        # The runner splits scenarios.sh at case headers for --case subsets and
        # profile skip lists, so a function defined in one case is missing when
        # another case that calls it runs without it.
        text = (ROOT / real_ssh.SCENARIOS).read_text()
        self.assertEqual(functions_used_elsewhere(text), [],
                         "define shared functions before the first case")

    def test_detects_a_function_from_another_case(self):
        text = ("shared() { :; }\n"
                "printf 'case: one\\n'\n"
                "helper() { :; }\nhelper\nshared\n"
                "printf 'case: two\\n'\n"
                "helper\nshared\n"
                "printf 'case: three\\n'\n"
                "helper() { true; }\nhelper\n"
                f"{real_ssh.FINAL_CHECKS}\n")
        self.assertEqual(functions_used_elsewhere(text),
                         [("helper", "one", "two"), ("helper", "three", "two")])


if __name__ == "__main__":
    unittest.main()
