#!/usr/bin/env python3
"""Check Nix dependency reuse and invalidation without compiling the product."""
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def output(tree, package):
    return subprocess.check_output([
        "nix", "--extra-experimental-features", "nix-command flakes", "eval",
        "--no-update-lock-file", "--raw", f"path:{tree}#{package}.outPath",
    ], text=True).strip()


with tempfile.TemporaryDirectory(prefix="syq-release-cache-") as tmp:
    tree = pathlib.Path(tmp)
    for name in ("flake.nix", "flake.lock", "Cargo.toml", "Cargo.lock",
                 "build.rs", "rust-toolchain.toml", "src", "nix"):
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, tree / name)
        else:
            shutil.copyfile(source, tree / name)
    deps = output(tree, "release-deps")
    release = output(tree, "release")
    source = tree / "src/main.rs"
    source.write_text(source.read_text() + "\n// Dependency-cache fixture.\n")
    assert output(tree, "release-deps") == deps, "source edit invalidated dependencies"
    assert output(tree, "release") != release, "source edit reused the final binary"

    import tomllib
    manifest = tree / "Cargo.toml"
    old = tomllib.loads(manifest.read_text())["package"]["version"]
    for name in ("Cargo.toml", "Cargo.lock"):
        path = tree / name
        before = f'name = "syq"\nversion = "{old}"'
        assert path.read_text().count(before) == 1
        path.write_text(path.read_text().replace(before, 'name = "syq"\nversion = "99.0.0"'))
    assert output(tree, "release-deps") == deps, "version bump invalidated dependencies"
    changed_release = output(tree, "release")
    assert changed_release != release, "version bump reused the final binary"

    manifest.write_text(manifest.read_text().replace('bytes = "1"',
                        'bytes = { version = "1", features = ["serde"] }'))
    assert output(tree, "release-deps") != deps, "dependency feature edit reused dependencies"
    shutil.copyfile(ROOT / "Cargo.toml", manifest)
    shutil.copyfile(ROOT / "Cargo.lock", tree / "Cargo.lock")
    manifest.write_text(manifest.read_text().replace('opt-level = 3', 'opt-level = 2'))
    assert output(tree, "release-deps") != deps, "optimization edit reused dependencies"
    print("Release cache preserves source/version reuse and invalidates dependency/profile changes.")
