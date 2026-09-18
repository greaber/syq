#!/usr/bin/env python3
"""Normalize maturin's local source references without dropping its Rust SBOM."""

import argparse
import base64
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import zipfile


def normalize(wheel: Path) -> None:
    temporary_path = None
    try:
        with zipfile.ZipFile(wheel) as source:
            infos = source.infolist()
            contents = {info.filename: source.read(info) for info in infos}
            sbom_name, = (n for n in contents if n.endswith(".dist-info/sboms/syq.cyclonedx.json"))
            record_name, = (n for n in contents if n.endswith(".dist-info/RECORD"))
            sbom = json.loads(contents[sbom_name])
            reference = sbom["metadata"]["component"]["bom-ref"]
            if not reference.startswith("path+file://") or "#syq@" not in reference:
                raise ValueError("unexpected local crate reference in maturin SBOM")
            prefix = reference.split("#", 1)[0] + "#"

            def rewrite(value):
                if isinstance(value, dict):
                    return {key: rewrite(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [rewrite(item) for item in value]
                if isinstance(value, str) and value.startswith(prefix):
                    return "path+file:///build/source#" + value[len(prefix):]
                return value

            contents[sbom_name] = json.dumps(
                rewrite(sbom), separators=(",", ":"), ensure_ascii=False,
            ).encode()
            # Keep RECORD's ordering and every archive member. Only the SBOM's
            # digest/size changes; the RECORD entry itself remains unhashed.
            record = io.StringIO(newline="")
            writer = csv.writer(record, lineterminator="\n")
            for name, digest, size in csv.reader(io.StringIO(contents[record_name].decode())):
                if name == sbom_name:
                    data = contents[name]
                    digest = "sha256=" + base64.urlsafe_b64encode(
                        hashlib.sha256(data).digest(),
                    ).rstrip(b"=").decode()
                    size = str(len(data))
                writer.writerow([name, digest, size])
            contents[record_name] = record.getvalue().encode()
            with tempfile.NamedTemporaryFile(dir=wheel.parent, suffix=".whl", delete=False) as temporary:
                temporary_path = Path(temporary.name)
                with zipfile.ZipFile(temporary, "w") as destination:
                    destination.comment = source.comment
                    for info in infos:
                        destination.writestr(copy.copy(info), contents[info.filename])
        temporary_path.chmod(wheel.stat().st_mode)
        temporary_path.replace(wheel)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    for wheel in parser.parse_args().wheels:
        normalize(wheel)
