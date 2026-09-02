from __future__ import annotations

import inspect
import json
import unittest
from pathlib import Path

import syq


def _python_name(option: str) -> str:
    name = option.replace("-", "_")
    return f"{name}_" if name in {"as", "from"} else name


class NativeApiInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        inventory_path = Path(__file__).resolve().parents[1] / "native-api.json"
        cls.inventory = json.loads(inventory_path.read_bytes())

    def test_every_python_option_is_in_the_matching_signature(self) -> None:
        sdk_parameters = {
            "cp": {"self", "sources", "on_event", "timeout", "check"},
            "map": {"self", "sources", "timeout"},
        }
        for command, classified in self.inventory["commands"].items():
            if classified["sdk"] != "python":
                continue
            with self.subTest(command=command):
                python_name = command.replace("-", "_")
                method = getattr(syq.Client, python_name)
                module_function = getattr(syq, python_name)
                expected = {_python_name(option) for option in classified["python"]}
                parameters = set(inspect.signature(method).parameters)
                self.assertEqual(parameters - sdk_parameters[command], expected)
                method_signature = inspect.signature(method)
                method_without_self = inspect.Signature(
                    list(method_signature.parameters.values())[1:],
                    return_annotation=method_signature.return_annotation,
                )
                self.assertEqual(
                    inspect.signature(module_function), method_without_self
                )
                async_signature = inspect.signature(
                    getattr(syq.AsyncClient, python_name)
                )
                self.assertEqual(set(async_signature.parameters), parameters)
                self.assertEqual(
                    [
                        (parameter.name, parameter.kind, parameter.default)
                        for parameter in async_signature.parameters.values()
                    ],
                    [
                        (parameter.name, parameter.kind, parameter.default)
                        for parameter in method_signature.parameters.values()
                    ],
                )


if __name__ == "__main__":
    unittest.main()
