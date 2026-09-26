#!/usr/bin/env python3
"""Sign one release manifest with the protected Ed25519 key and prove that key
matches the public key embedded in official binaries.

Usage: scripts/sign-release-manifest.py MANIFEST SYQ_BINARY

Reads SYQ_RELEASE_SIGNING_KEY_PEM_B64 and SYQ_RELEASE_PUBLIC_KEY. The private
key stays in memory: OpenSSL 3 reads it from a pipe, never from a file.
"""
import base64
import binascii
import json
import os
import shutil
import subprocess
import sys
import tempfile


class SigningError(Exception):
    pass


def openssl(*args, data=None):
    """Run openssl with `data` on stdin and return its stdout."""
    completed = subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE)
    if completed.returncode:
        raise SigningError(f"openssl {args[0]} failed with exit status {completed.returncode}")
    return completed.stdout


def decode(name, value):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise SigningError(f"{name} is not valid base64") from None


def canonical_payload(canonicalizer, manifest):
    completed = subprocess.run([canonicalizer, "--release-manifest-signing-payload", manifest],
                               stdout=subprocess.PIPE)
    if completed.returncode:
        raise SigningError(f"{canonicalizer} could not canonicalize {manifest}")
    return completed.stdout


def require_ed25519_openssl():
    # Ed25519 raw signing with pkeyutl needs OpenSSL 3. macOS ships LibreSSL as
    # `openssl`, and OpenSSL 1.1.1 lacks `pkeyutl -rawin`; Homebrew's openssl@3
    # works once its bin directory is first on PATH.
    help_text = subprocess.run(["openssl", "pkeyutl", "-help"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT).stdout
    if b"-rawin" not in help_text:
        version = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True)
        found = version.stdout.strip() if version.returncode == 0 else "unknown"
        raise SigningError(f"{sys.argv[0]} needs OpenSSL 3 for Ed25519 raw signing; found: {found}\n"
                           "on macOS, install openssl@3 with Homebrew and put its bin directory "
                           "first on PATH")


def unsigned_manifest(path):
    try:
        with open(path, encoding="utf-8") as source:
            manifest = json.load(source)
    except (OSError, ValueError):
        return None
    if (isinstance(manifest, dict) and manifest.get("signature_scheme") == "ed25519-jcs-v1"
            and "signature" not in manifest):
        return manifest
    return None


def sign(manifest_path, canonicalizer, signing_key_b64, public_key_b64):
    require_ed25519_openssl()
    manifest = unsigned_manifest(manifest_path)
    if manifest is None:
        raise SigningError("release manifest is not unsigned ed25519-jcs-v1 metadata")

    # A secret stored from a file often ends in a newline; base64 never
    # contains whitespace, so ignore it as `openssl base64 -d -A` did.
    private_pem = decode("SYQ_RELEASE_SIGNING_KEY_PEM_B64", "".join(signing_key_b64.split()))
    if len(decode("SYQ_RELEASE_PUBLIC_KEY", public_key_b64)) != 32:
        raise SigningError("SYQ_RELEASE_PUBLIC_KEY must encode exactly 32 bytes")
    public_pem = openssl("pkey", "-pubout", data=private_pem)
    der = openssl("pkey", "-pubout", "-outform", "DER", data=private_pem)
    if base64.b64encode(der[-32:]).decode() != public_key_b64:
        raise SigningError("The signing key does not match SYQ_RELEASE_PUBLIC_KEY.")

    with tempfile.TemporaryDirectory(prefix="syq-sign-release.") as work:
        payload_path = os.path.join(work, "manifest.jcs")
        signature_path = os.path.join(work, "embedded.sig")
        signed_path = os.path.join(work, "signed-manifest.json")

        def verify(payload):
            with open(payload_path, "wb") as output:
                output.write(payload)
            openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "/dev/stdin",
                    "-in", payload_path, "-sigfile", signature_path, data=public_pem)

        payload = canonical_payload(canonicalizer, manifest_path)
        with open(payload_path, "wb") as output:
            output.write(payload)
        signature = openssl("pkeyutl", "-sign", "-rawin", "-inkey", "/dev/stdin",
                            "-in", payload_path, data=private_pem)
        with open(signature_path, "wb") as output:
            output.write(signature)
        verify(payload)

        manifest["signature"] = base64.b64encode(signature).decode()
        with open(signed_path, "w", encoding="utf-8") as output:
            output.write(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        verified_payload = canonical_payload(canonicalizer, signed_path)
        if verified_payload != payload:
            raise SigningError("embedded signature changed the canonical manifest payload")
        verify(verified_payload)
        os.chmod(signed_path, 0o644)
        shutil.move(signed_path, manifest_path)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} MANIFEST SYQ_BINARY", file=sys.stderr)
        return 2
    manifest, canonicalizer = sys.argv[1:]
    public_key = os.environ.get("SYQ_RELEASE_PUBLIC_KEY", "")
    signing_key = os.environ.get("SYQ_RELEASE_SIGNING_KEY_PEM_B64", "")
    for problem, message in [
            (not os.path.isfile(manifest) or os.path.islink(manifest),
             f"missing regular release manifest: {manifest}"),
            (not os.access(canonicalizer, os.X_OK),
             f"missing executable syq canonicalizer: {canonicalizer}"),
            (not public_key, "SYQ_RELEASE_PUBLIC_KEY is not set"),
            (not signing_key, "SYQ_RELEASE_SIGNING_KEY_PEM_B64 is not set"),
            (not shutil.which("openssl"), "signing needs openssl")]:
        if problem:
            print(message, file=sys.stderr)
            return 1
    try:
        sign(manifest, canonicalizer, signing_key, public_key)
    except SigningError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
