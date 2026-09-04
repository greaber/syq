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
            "rm": {"self", "sources", "on_event", "timeout", "check"},
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

    def test_sync_and_async_clients_have_matching_public_methods(self) -> None:
        def public_methods(client: type) -> dict[str, object]:
            return {
                name: value
                for name, value in inspect.getmembers(client, inspect.isfunction)
                if not name.startswith("_")
            }

        sync = public_methods(syq.Client)
        async_ = public_methods(syq.AsyncClient)
        self.assertEqual(set(sync), {"cp", "rm", "map", "run", "version"})
        self.assertEqual(set(async_), set(sync))
        for name in sync:
            with self.subTest(method=name):
                sync_parameters = inspect.signature(sync[name]).parameters.values()
                async_parameters = inspect.signature(async_[name]).parameters.values()
                self.assertEqual(
                    [
                        (parameter.name, parameter.kind, parameter.default)
                        for parameter in async_parameters
                    ],
                    [
                        (parameter.name, parameter.kind, parameter.default)
                        for parameter in sync_parameters
                    ],
                )

    def test_sync_and_async_client_constructors_match(self) -> None:
        sync_parameters = inspect.signature(syq.Client).parameters.values()
        async_parameters = inspect.signature(syq.AsyncClient).parameters.values()
        self.assertEqual(
            [
                (parameter.name, parameter.kind, parameter.default)
                for parameter in async_parameters
            ],
            [
                (parameter.name, parameter.kind, parameter.default)
                for parameter in sync_parameters
            ],
        )


if __name__ == "__main__":
    unittest.main()
