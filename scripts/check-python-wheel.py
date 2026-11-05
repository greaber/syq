#!/usr/bin/env python3
"""Exercise an installed wheel without PATH lookup, downloads, or a home cache."""

import argparse
import asyncio
import os
from importlib.metadata import metadata
from pathlib import Path
import tempfile
from unittest.mock import patch

import syq
from syq.bundled import bundled_executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True,
                        help="the release the bundled syq is, or a development build of")
    parser.add_argument("--identity", help="the bundled syq's exact build identity")
    args = parser.parse_args()
    assert metadata("syq")["Requires-Python"] == ">=3.13.4", (
        "wheel must require Python 3.13.4 or newer"
    )
    expected_readme = Path(__file__).resolve().parent.parent / "sdk/python/README-PYTHON.md"
    assert metadata("syq").get_payload().strip() == expected_readme.read_text().strip(), (
        "wheel long description does not match the Python README"
    )
    with tempfile.TemporaryDirectory(prefix="syq-wheel-") as directory:
        root = Path(directory).resolve()
        unavailable = root / "not-a-directory"
        unavailable.write_text("No writable home or cache")
        with patch.dict(os.environ, {
            "HOME": str(unavailable), "XDG_CACHE_HOME": str(unavailable),
            "PATH": str(unavailable),
        }), patch("urllib.request.urlopen", side_effect=AssertionError("unexpected download")):
            executable = bundled_executable()
            assert executable.is_file(), executable
            identity = syq.run(["--build-identity"]).stdout.decode().strip()
            if args.identity:
                assert identity == args.identity, identity
            # A development build, including one from the source archive,
            # reports its build identity as its version.
            release = f"v{args.version}"
            assert identity == release or identity.startswith(f"{release}+dev."), identity
            version = identity.removeprefix("v")
            assert syq.version() == version, syq.version()
            (root / "source").write_bytes(b"bundled CLI copy\n")
            client = syq.Client(process_cwd=root)
            result = client.cp("source", as_new="copy")
            assert result.files_transferred == 1
            assert (root / "copy").read_bytes() == (root / "source").read_bytes()

            async def check_async():
                client = syq.AsyncClient(process_cwd=root)
                assert await client.version() == version
                await client.cp("source", as_new="async-copy")
                assert (root / "async-copy").read_bytes() == (root / "source").read_bytes()
                await client.rm("async-copy")

            asyncio.run(check_async())
            client.rm("copy")
            assert not (root / "copy").exists()
    print("Installed wheel: version, identity, sync/async copy and removal passed without download or home cache")


if __name__ == "__main__":
    main()
