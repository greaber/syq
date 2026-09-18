#!/usr/bin/env python3
"""Exercise release selection and generated navigation without network access."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from html.parser import HTMLParser

spec = importlib.util.spec_from_file_location("doc_site", Path(__file__).with_name("build-doc-site.py"))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)


class Options(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.options = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        if tag == "option":
            self.options.append(dict(attrs))


class DocumentationSite(unittest.TestCase):
    versions = ["v0.6.0", "v0.5.2", "master"]
    pages = {
        "v0.6.0": {"index.html", "reference.html", "commands/cp.html"},
        "v0.5.2": {"index.html", "reference.html"},
        "master": {"index.html", "reference.html", "commands/cp.html", "new.html"},
    }

    def test_only_published_stable_product_releases_in_numeric_order(self):
        def release(tag, **flags):
            return {"tag_name": tag, "draft": False, "prerelease": False, **flags}
        releases = [release("v0.9.0"), release("v0.10.0"), release("v0.10.0"),
                    release("v1.0.0", draft=True), release("v0.11.0", prerelease=True),
                    release("v0.12.0-rc.1"), release("sdk-python-v2.0.0"),
                    release("sdk/go/v2.0.0")]
        self.assertEqual(site.release_tags(releases), ["v0.10.0", "v0.9.0"])

    def test_switch_preserves_nested_pages_and_falls_back_when_absent(self):
        markup = site.switcher("master", "commands/cp.html", self.versions, self.pages)
        options = Options(markup).options
        self.assertEqual(options[0]["value"], "/syq/v0.6.0/commands/cp.html")
        self.assertEqual(options[0]["data-same-page"], "true")
        self.assertEqual(options[1]["value"], "/syq/v0.5.2/index.html")
        self.assertEqual(options[1]["data-same-page"], "false")
        self.assertIn("selected", options[2])
        self.assertIn("master — unreleased", markup)
        self.assertIn("v0.6.0 (latest)", markup)

    def test_missing_page_goes_home_in_every_version(self):
        for option in Options(site.switcher("master", "404.html", self.versions, self.pages)).options:
            self.assertTrue(option["value"].endswith("/index.html"))
            self.assertEqual(option["data-same-page"], "false")

    def test_decorates_nested_pages_and_preserves_mdbook_redirects(self):
        with tempfile.TemporaryDirectory() as temporary:
            book = Path(temporary) / "v0.6.0"
            (book / "commands").mkdir(parents=True)
            page = book / "commands/cp.html"
            page.write_text('<html><head></head><body><a href="https://greaber.github.io/syq/">'
                            'Documentation</a><main><h1>Copy</h1>'
                            '<a href="https://greaber.github.io/syq/reference.html#copy">Reference</a>'
                            '</main></body></html>')
            redirect = book / "legacy.html"
            original = '<html><head><meta http-equiv="refresh" content="0;url=index.html"></head></html>'
            redirect.write_text(original)
            site.decorate(book, "v0.6.0", self.versions, self.pages)
            result = page.read_text()
            self.assertIn('href="/syq/v0.6.0/"', result)
            self.assertIn('src="/syq/version-selector.js" defer', result)
            self.assertIn('<h1>Copy</h1>', result)
            self.assertIn('href="/syq/v0.6.0/reference.html#copy"', result)
            self.assertEqual(len(Options(result).options), 3)
            self.assertEqual(redirect.read_text(), original)

    def test_old_root_links_to_unreleased_pages_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_text("stable home")
            site.legacy_redirects(root, self.pages, "v0.6.0")
            self.assertEqual((root / "index.html").read_text(), "stable home")
            redirect = (root / "new.html").read_text()
            self.assertIn('/syq/master/new.html', redirect)
            self.assertIn('location.search + location.hash', redirect)
            self.assertFalse((root / "commands/cp.html").exists())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "output already exists"):
                site.build_site(Path(temporary), [])

    def test_no_stable_release_fails_before_building(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "no published stable"):
                site.build_site(Path(temporary) / "new", [])


if __name__ == "__main__":
    unittest.main()
