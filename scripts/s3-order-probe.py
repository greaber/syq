#!/usr/bin/env python3
"""Check how an S3-compatible service orders and pages ListObjectsV2.

syq divides a listing into parts, and decides a key absent from where it
would fall in a page, only where the service lists keys in UTF-8 byte order.
For a service that does not document its order, run this before relying on
it, and again later to notice a change. It runs against a real service by
hand and is not part of CI.

usage: scripts/s3-order-probe.py --endpoint URL [--region REGION] s3://BUCKET[/PREFIX]

Credentials come from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and, if set,
AWS_SESSION_TOKEN. The bucket must allow writing: the probe uploads about 150
one-byte objects under a new prefix `syq-order-probe-<random>/` below PREFIX,
lists them, and deletes them again, also when it fails. It addresses buckets
path-style. Keys a service refuses to store, such as a key and a "directory"
of the same name on MinIO, are reported under not_stored and left out of the
checks.

It checks:
  flat-order       flat listings at several page sizes return every key once,
                   in UTF-8 byte order;
  start-after      a flat listing that starts after a key resumes at the next
                   key in byte order;
  delimiter-pages  delimiter listings at several page sizes return every key
                   and common prefix once, including the key `P0` after a page
                   that ends with the common prefix `P/`;
  distinct-forms   keys that differ only in Unicode normalization (NFC and NFD
                   spellings of "é") are stored as two objects.

It prints a JSON report on stdout, one line per check on stderr, and exits 0
when every check passes, 1 when one fails, and 2 when the probe could not run
or clean up.
"""
import argparse
import datetime
import hashlib
import hmac
import json
import os
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

NFC_E = unicodedata.normalize("NFC", "é")
NFD_E = unicodedata.normalize("NFD", "é")
PAGE_SIZES = (1, 3, 7, 1000)


def keys():
    """Relative keys, chosen so that orders other than bytes show."""
    names = [
        # Keys that extend others with bytes below and above '9', '/' and '.'.
        "a", "a0", "a1", "a9", "a:", "a/b", "a/", "a.b", "a-b", "a!", "a~", "ab", "aA",
        "a b", "a.png", "a.png.metadata.json", "a.png/x", "k19", "k190", "k199", "k2",
        # Case and punctuation.
        "A", "B", "b", "Z", "z", "_", "~", "[", "`", "{", "0", "9",
        # Bytes above ASCII: Latin, CJK, emoji, fullwidth, and the two forms.
        "ÿ", "Ā", "日本", "\U0001f600", "\U0001f600/x", "Ａ",
        "e" + NFC_E, "e" + NFD_E,
        # Characters that need encoding in a URL.
        "%", "%25", "a%2Fb", "+", "a+b", " x", "x ",
    ]
    out = ["o/" + name for name in names]
    # Delimiter pages: directories followed by a key that extends their name
    # with '0', at every page boundary for small page sizes.
    for stem in ("x", "y", "q", "q0", "r"):
        out += [f"d/{stem}/a", f"d/{stem}0", f"d/{stem}1/a"]
    out += [f"d/f{i:02d}" for i in range(12)]
    out += [f"d/q00", "d/q01/a"]
    return sorted(set(out), key=lambda key: key.encode())


class Client:
    def __init__(self, endpoint, region, bucket):
        self.endpoint = endpoint.rstrip("/")
        self.region = region
        self.bucket = bucket
        self.key_id = os.environ["AWS_ACCESS_KEY_ID"]
        self.secret = os.environ["AWS_SECRET_ACCESS_KEY"]
        self.token = os.environ.get("AWS_SESSION_TOKEN")

    def request(self, method, key="", query=None, data=b""):
        quote = lambda text, safe="-_.~": urllib.parse.quote(text, safe=safe)
        path = "/" + quote(self.bucket) + "/" + quote(key, safe="-_.~/")
        query = "&".join(f"{quote(k)}={quote(v)}" for k, v in sorted((query or {}).items()))
        now = datetime.datetime.now(datetime.timezone.utc)
        date, stamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
        digest = hashlib.sha256(data).hexdigest()
        headers = {"host": urllib.parse.urlsplit(self.endpoint).netloc, "x-amz-date": stamp,
                   "x-amz-content-sha256": digest}
        if self.token:
            headers["x-amz-security-token"] = self.token
        names = ";".join(sorted(headers))
        canonical = "\n".join([method, path, query,
                               "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers)),
                               names, digest])
        scope = f"{date}/{self.region}/s3/aws4_request"
        signed = "\n".join(["AWS4-HMAC-SHA256", stamp, scope,
                            hashlib.sha256(canonical.encode()).hexdigest()])
        secret = ("AWS4" + self.secret).encode()
        for item in (date, self.region, "s3", "aws4_request"):
            secret = hmac.new(secret, item.encode(), hashlib.sha256).digest()
        signature = hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.key_id}/{scope}, "
                                    f"SignedHeaders={names}, Signature={signature}")
        url = self.endpoint + path + ("?" + query if query else "")
        request = urllib.request.Request(url, method=method, headers=headers,
                                         data=data if method == "PUT" else None)
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()

    def page(self, prefix, max_keys, token=None, start_after=None, delimiter=False):
        """One ListObjectsV2 page: items in the order returned, and the next token."""
        query = {"list-type": "2", "prefix": prefix, "max-keys": str(max_keys), "encoding-type": "url"}
        if token:
            query["continuation-token"] = token
        if start_after:
            query["start-after"] = start_after
        if delimiter:
            query["delimiter"] = "/"
        root = ET.fromstring(self.request("GET", query=query))
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
        encoded = (root.findtext("EncodingType") or "").lower() == "url"
        decode = (lambda text: urllib.parse.unquote_plus(text)) if encoded else (lambda text: text)
        items = []
        for node in root:
            if node.tag == "Contents":
                items.append(("key", decode(node.findtext("Key"))))
            elif node.tag == "CommonPrefixes":
                items.append(("prefix", decode(node.findtext("Prefix"))))
        truncated = root.findtext("IsTruncated") == "true"
        return items, root.findtext("NextContinuationToken") if truncated else None

    def listing(self, prefix, max_keys, delimiter=False):
        items, token, pages = [], None, 0
        while True:
            page, token = self.page(prefix, max_keys, token=token, delimiter=delimiter)
            items += page
            pages += 1
            if not token or pages > 10_000:
                return items


def expected_items(stored, prefix):
    """What a delimiter listing of `prefix` holds: keys and common prefixes."""
    items = set()
    for key in stored:
        if key.startswith(prefix):
            rest = key[len(prefix):]
            items.add(("prefix", prefix + rest[:rest.index("/") + 1]) if "/" in rest else ("key", key))
    return items


def run(client, root, stored):
    report = {"prefix": root, "checks": {}}
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda key: client.request("PUT", key, data=b"x"), stored))
    forms = {root + "o/e" + NFC_E, root + "o/e" + NFD_E}
    # What the service holds. Some cannot store a key and a "directory" of
    # the same name; a key acknowledged but never listed is checked by HEAD.
    present = set(key for kind, key in client.listing(root, 1000))
    unlisted, unstored = [], []
    for key in sorted(set(stored) - present - forms):
        try:
            client.request("HEAD", key)
            unlisted.append(key)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            unstored.append(key)
    report["not_stored"] = unstored

    # Flat order and completeness. A service that merges the two forms of a
    # name lists one of them; distinct-forms reports that.
    flat = []
    for size in PAGE_SIZES:
        got = [key for kind, key in client.listing(root + "o/", size)]
        out_of_order = [(a, b) for a, b in zip(got, got[1:]) if a.encode() >= b.encode()]
        missing = sorted({k for k in present if k.startswith(root + "o/")} - set(got))
        flat.append({"page_size": size, "out_of_order": out_of_order[:10],
                     "missing": missing[:10], "duplicates": len(got) - len(set(got))})
    report["checks"]["flat-order"] = {
        "pass": not unlisted and all(not r["out_of_order"] and not r["missing"] and not r["duplicates"]
                                     for r in flat),
        "stored_but_never_listed": unlisted[:10], "pages": flat}

    # StartAfter: each key's successor in byte order comes next.
    order = sorted((k for k in present if k.startswith(root + "o/")), key=lambda k: k.encode())
    wrong = []
    for before, after in zip(order, order[1:]):
        page, _ = client.page(root + "o/", 1, start_after=before)
        got = page[0][1] if page else None
        if got != after:
            wrong.append({"start_after": before, "expected": after, "got": got})
    report["checks"]["start-after"] = {"pass": not wrong, "wrong": wrong[:10]}

    # Delimiter pages at sizes that put a common prefix last on some page.
    expected = expected_items(present, root + "d/")
    pages = []
    for size in (1, 2, 3, 4, 5, 6, 1000):
        got = client.listing(root + "d/", size, delimiter=True)
        pages.append({"page_size": size,
                      "missing": sorted(item for _, item in expected - set(got))[:10],
                      "extra": sorted(item for _, item in set(got) - expected)[:10],
                      "duplicates": len(got) - len(set(got))})
    report["checks"]["delimiter-pages"] = {
        "pass": all(not r["missing"] and not r["extra"] and not r["duplicates"] for r in pages),
        "pages": pages}

    report["checks"]["distinct-forms"] = {"pass": forms <= present}
    return report


def clean(client, root, stored):
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda key: client.request("DELETE", key), stored))
    # Delete whatever else is there, such as a merged spelling.
    left = [key for _, key in client.listing(root, 1000)]
    for key in left:
        client.request("DELETE", key)
    return [key for _, key in client.listing(root, 1000)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--endpoint", required=True, help="the service's S3 endpoint URL")
    parser.add_argument("--region", default="us-east-1", help="signing region (default us-east-1)")
    parser.add_argument("location", help="s3://BUCKET or s3://BUCKET/PREFIX/ to probe under")
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.location)
    if parsed.scheme != "s3" or not parsed.netloc:
        parser.error("the location must look like s3://BUCKET or s3://BUCKET/PREFIX/")
    base = parsed.path.lstrip("/")
    if base and not base.endswith("/"):
        base += "/"
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if not os.environ.get(name):
            parser.error(f"{name} is not set")
    client = Client(args.endpoint, args.region, parsed.netloc)
    root = base + f"syq-order-probe-{uuid.uuid4().hex[:12]}/"
    stored = [root + key for key in keys()]
    report = None
    try:
        report = run(client, root, stored)
    except (urllib.error.URLError, ET.ParseError, OSError) as error:
        print(f"s3-order-probe: {error}", file=sys.stderr)
    finally:
        cleaned = False
        try:
            left = clean(client, root, stored)
            cleaned = not left
            if left:
                print(f"s3-order-probe: {len(left)} objects left under {root}", file=sys.stderr)
        except (urllib.error.URLError, ET.ParseError, OSError) as error:
            print(f"s3-order-probe: cleaning up {root}: {error}", file=sys.stderr)
    if report is None or not cleaned:
        return 2
    json.dump(report, sys.stdout, indent=1, ensure_ascii=False)
    print()
    for name, check in report["checks"].items():
        print(f"{name}: {'pass' if check['pass'] else 'FAIL'}", file=sys.stderr)
    return 0 if all(check["pass"] for check in report["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
