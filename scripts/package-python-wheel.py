#!/usr/bin/env python3
"""Assemble a reproducible wheel around the exact published native executable."""

import argparse
import base64
import csv
from email.parser import Parser
import hashlib
import io
import json
from pathlib import Path
import time
import tomllib
import zipfile

PLATFORMS = {
    "linux-x86_64": "manylinux_2_5_x86_64.manylinux1_x86_64",
    "linux-aarch64": "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "macos-x86_64": "macosx_10_12_x86_64",
    "macos-arm64": "macosx_11_0_arm64",
}


def package(project, metadata, binary, platform, sbom, epoch, output):
    config = tomllib.loads((project / "pyproject.toml").read_text())
    version = config["project"]["version"]
    manifest = json.loads((project / "src/syq/syq-release-manifest.json").read_text())
    if manifest["version"] != version or manifest["tag"] != f"v{version}":
        raise ValueError("Python version does not match the native release")
    payload = binary.read_bytes()
    expected = manifest["artifacts"][platform]["binary"]
    if len(payload) != expected["size"] or hashlib.sha256(payload).hexdigest() != expected["sha256"]:
        raise ValueError("Binary does not match the release manifest")
    distribution = f"syq-{version}"
    info = f"{distribution}.dist-info"
    generated = metadata / info
    fields = Parser().parsestr((generated / "METADATA").read_text())
    if fields["Name"] != "syq" or fields["Version"] != version:
        raise ValueError("Unexpected generated package metadata")
    # Keep the existing .data/scripts layout consumed by bundled_executable().
    members = {f"{distribution}.data/scripts/syq": (payload, 0o755)}
    for base, prefix in ((project / "src/syq", "syq"), (generated, info)):
        for path in sorted(base.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                name = f"{prefix}/{path.relative_to(base).as_posix()}"
                if name not in (f"{info}/WHEEL", f"{info}/RECORD"):
                    members[name] = (path.read_bytes(), 0o644)
    tags = [f"py3-none-{tag}" for tag in PLATFORMS[platform].split(".")]
    wheel = "Wheel-Version: 1.0\nGenerator: syq release wheel\nRoot-Is-Purelib: false\n"
    wheel += "".join(f"Tag: {tag}\n" for tag in tags)
    members[f"{info}/WHEEL"] = (wheel.encode(), 0o644)
    members[f"{info}/sboms/syq.cyclonedx.json"] = (sbom.read_bytes(), 0o644)
    record_name = f"{info}/RECORD"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, (data, _) in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", len(data)))
    writer.writerow((record_name, "", ""))
    members[record_name] = (record.getvalue().encode(), 0o644)
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"{distribution}-py3-none-{PLATFORMS[platform]}.whl"
    stamp = time.gmtime(max(epoch, 315532800))[:6]  # ZIP timestamps start in 1980.
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        # Put metadata last, as recommended by the wheel specification.
        for name in sorted(members, key=lambda name: (name.startswith(info + "/"), name)):
            data, mode = members[name]
            entry = zipfile.ZipInfo(name, stamp)
            entry.create_system = 3
            entry.external_attr = (0o100000 | mode) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compresslevel=9)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "metadata", "binary", "sbom", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--platform", choices=PLATFORMS, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    print(package(args.project, args.metadata, args.binary, args.platform,
                  args.sbom, args.epoch, args.out))
