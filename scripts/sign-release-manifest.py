#!/usr/bin/env python3
"""Sign one release manifest with the protected Ed25519 key and prove that key
matches the public key embedded in official binaries.

Usage: scripts/sign-release-manifest.py MANIFEST SYQ_BINARY

Reads SYQ_RELEASE_SIGNING_KEY_PEM_B64 and SYQ_RELEASE_PUBLIC_KEY. OpenSSL 3
performs every cryptographic and base64 operation.
"""
import os
import shutil
import subprocess
import sys
import tempfile

from tooling import JqError, dumps, exit_on_failure, get, load_file


def fail(message):
    print(message, file=sys.stderr)
    return 1


def openssl(*args, data=None, stdout=subprocess.PIPE):
    """Run openssl; a failure exits with its status, as under `set -e`."""
    completed = subprocess.run(["openssl", *args], input=data, stdout=stdout)
    if completed.returncode:
        sys.exit(completed.returncode)
    return completed.stdout


def unsigned_manifest(path):
    try:
        manifest = load_file(path)
        return (isinstance(manifest, dict)
                and get(manifest, "signature_scheme") == "ed25519-jcs-v1"
                and "signature" not in manifest)
    except (JqError, UnicodeDecodeError):
        return False


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} MANIFEST SYQ_BINARY", file=sys.stderr)
        return 2
    manifest, canonicalizer = sys.argv[1:]
    if not os.path.isfile(manifest) or os.path.islink(manifest):
        return fail(f"missing regular release manifest: {manifest}")
    if not os.access(canonicalizer, os.X_OK):
        return fail(f"missing executable syq canonicalizer: {canonicalizer}")
    public_key = os.environ.get("SYQ_RELEASE_PUBLIC_KEY", "")
    signing_key = os.environ.get("SYQ_RELEASE_SIGNING_KEY_PEM_B64", "")
    if not public_key:
        return fail("SYQ_RELEASE_PUBLIC_KEY is not set")
    if not signing_key:
        return fail("SYQ_RELEASE_SIGNING_KEY_PEM_B64 is not set")
    if not shutil.which("openssl"):
        return fail("signing needs openssl")

    # Ed25519 raw signing with pkeyutl needs OpenSSL 3. macOS ships LibreSSL as
    # `openssl`, and OpenSSL 1.1.1 lacks `pkeyutl -rawin`; Homebrew's openssl@3
    # works once its bin directory is first on PATH.
    help_text = subprocess.run(["openssl", "pkeyutl", "-help"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT).stdout
    if b"-rawin" not in help_text:
        found = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
        found = found.stdout.rstrip("\n") if found.returncode == 0 else "unknown"
        print(f"{sys.argv[0]} needs OpenSSL 3 for Ed25519 raw signing; found: {found}",
              file=sys.stderr)
        return fail("on macOS, install openssl@3 with Homebrew and put its bin directory "
                    "first on PATH")
    if not unsigned_manifest(manifest):
        return fail("release manifest is not unsigned ed25519-jcs-v1 metadata")

    os.umask(0o077)
    work = tempfile.mkdtemp(prefix="syq-sign-release.")
    try:
        return sign(manifest, canonicalizer, signing_key, public_key, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sign(manifest, canonicalizer, signing_key, public_key, work):
    key = os.path.join(work, "signing.pem")
    public = os.path.join(work, "public.pem")
    payload = os.path.join(work, "manifest.jcs")
    verified_payload = os.path.join(work, "verified-manifest.jcs")
    embedded_signature = os.path.join(work, "embedded.sig")
    signed_manifest = os.path.join(work, "signed-manifest.json")
    configured_public = os.path.join(work, "configured-public-key")

    with open(key, "wb") as output:
        openssl("base64", "-d", "-A", data=os.fsencode(signing_key), stdout=output)
    openssl("pkey", "-in", key, "-pubout", "-out", public, stdout=subprocess.DEVNULL)
    with open(configured_public, "wb") as output:
        openssl("base64", "-d", "-A", data=os.fsencode(public_key), stdout=output)
    if os.path.getsize(configured_public) != 32:
        return fail("SYQ_RELEASE_PUBLIC_KEY must encode exactly 32 bytes")
    der = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
    derived = openssl("base64", "-A", data=der[-32:]).decode().rstrip("\n")
    if derived != public_key:
        return fail("The signing key does not match SYQ_RELEASE_PUBLIC_KEY.")

    canonicalize(canonicalizer, manifest, payload)
    openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", payload,
            "-out", embedded_signature)
    openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-in", payload,
            "-sigfile", embedded_signature, stdout=subprocess.DEVNULL)
    embedded_b64 = openssl("base64", "-A", "-in", embedded_signature).decode().rstrip("\n")
    signed = load_file(manifest)
    signed["signature"] = embedded_b64
    with open(signed_manifest, "w", encoding="utf-8") as output:
        output.write(dumps(signed, indent=2, sort_keys=True) + "\n")
    canonicalize(canonicalizer, signed_manifest, verified_payload)
    with open(payload, "rb") as first, open(verified_payload, "rb") as second:
        if first.read() != second.read():
            return fail("embedded signature changed the canonical manifest payload")
    openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-in", verified_payload,
            "-sigfile", embedded_signature, stdout=subprocess.DEVNULL)

    os.chmod(signed_manifest, 0o644)
    shutil.move(signed_manifest, manifest)
    return 0


def canonicalize(canonicalizer, manifest, payload):
    with open(payload, "wb") as output:
        completed = subprocess.run([canonicalizer, "--release-manifest-signing-payload", manifest],
                                   stdout=output)
    if completed.returncode:
        sys.exit(completed.returncode)


if __name__ == "__main__":
    sys.exit(exit_on_failure(main))
