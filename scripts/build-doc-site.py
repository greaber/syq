#!/usr/bin/env python3
"""Build the stable default, release archives, and development documentation."""

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SITE = "/syq/"
REPOSITORY = "greaber/syq"


def release_tags(releases):
    """Only published stable syq releases, newest version first (not SDK tags)."""
    tags = {
        release["tag_name"]
        for release in releases
        if not release["draft"] and not release["prerelease"]
        and re.fullmatch(r"v\d+\.\d+\.\d+", release["tag_name"])
    }
    return sorted(tags, key=lambda tag: tuple(map(int, tag[1:].split("."))), reverse=True)


def published_releases():
    pages = json.loads(subprocess.check_output([
        "gh", "api", "--paginate", "--slurp", f"repos/{REPOSITORY}/releases?per_page=100"
    ], text=True))
    return [release for page in pages for release in page]


def build_book(source, destination, version, prefix):
    env = dict(os.environ)
    env.update({
        "MDBOOK_OUTPUT__HTML__SITE_URL": prefix,
        "MDBOOK_OUTPUT__HTML__GIT_REPOSITORY_URL":
            f"https://github.com/{REPOSITORY}/tree/{version}",
        # An archived page cannot be edited on its release tag.
        "MDBOOK_OUTPUT__HTML__EDIT_URL_TEMPLATE":
            f"https://github.com/{REPOSITORY}/edit/master/{{path}}" if version == "master" else "",
    })
    subprocess.run(["mdbook", "build", str(source), "--dest-dir", str(destination)],
                   env=env, check=True)


def switcher(version, page, versions, pages):
    options = []
    links = []
    for target in versions:
        label = "master — unreleased" if target == "master" else target
        if target == versions[0]:
            label += " (latest)"
        same_page = page in pages[target] and page != "404.html"
        destination = page if same_page else "index.html"
        url = f"{SITE}{target}/{destination}"
        selected = " selected" if target == version else ""
        options.append(
            f'<option value="{html.escape(url, quote=True)}"'
            f' data-same-page="{str(same_page).lower()}"{selected}>{html.escape(label)}</option>'
        )
        links.append(f'<a href="{SITE}{target}/">{html.escape(label)}</a>')
    return (
        '<nav class="docs-version" aria-label="Documentation version">'
        '<label for="docs-version-select">Documentation</label>'
        '<select id="docs-version-select" autocomplete="off">' + "".join(options) + '</select>'
        '<noscript><span>Choose a version: ' + " · ".join(links) + '</span></noscript></nav>'
    )


def decorate(book, version, versions, pages):
    for path in book.rglob("*.html"):
        text = path.read_text()
        # mdBook's redirect documents have no main element; leave them intact.
        if "<main>" not in text:
            continue
        page = path.relative_to(book).as_posix()
        text = text.replace("<main>", "<main>" + switcher(version, page, versions, pages), 1)
        text = text.replace("</head>",
                            f'<link rel="stylesheet" href="{SITE}version-selector.css">\n'
                            f'<script src="{SITE}version-selector.js" defer></script>\n</head>', 1)
        # Keep the shared brand header inside the selected documentation version.
        home = SITE if book.name == "default" else f"{SITE}{version}/"
        # Included SDK Markdown also uses absolute documentation links so it
        # works on GitHub/PyPI. Keep those links within this version on the site.
        text = text.replace(f'href="https://greaber.github.io{SITE}', f'href="{home}')
        path.write_text(text)


def legacy_redirects(destination, pages, latest):
    # These URLs previously served master. Keep bookmarks to unreleased pages
    # working, while all pages available in stable continue to default to stable.
    for page in pages["master"] - pages[latest]:
        target = f"{SITE}master/{page}"
        path = destination / page
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<title>Development documentation</title>'
            f'<meta http-equiv="refresh" content="0;url={target}">'
            f'<script>location.replace({json.dumps(target)} + location.search + location.hash);</script>'
            f'<p>This page documents an unreleased version. <a href="{target}">'
            'Read the master documentation</a>.</p></html>'
        )


def build_site(destination, releases):
    if destination.exists():
        raise ValueError(f"output already exists: {destination}; choose a fresh directory")
    tags = release_tags(releases)
    if not tags:
        raise ValueError("no published stable syq releases found")
    with tempfile.TemporaryDirectory(prefix="syq-docs-") as temporary:
        work = Path(temporary)
        books = work / "books"
        sources = work / "sources"
        books.mkdir()
        sources.mkdir()
        supported = []
        for tag in tags:
            # A missing fetched tag is an error, not an excuse to omit a release.
            commit = subprocess.check_output(
                ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
                cwd=ROOT, text=True).strip()
            files = subprocess.check_output(
                ["git", "ls-tree", "--name-only", commit], cwd=ROOT, text=True).splitlines()
            if "book.toml" not in files:
                if tag == tags[0]:
                    raise ValueError(f"latest release {tag} has no mdBook documentation")
                print(f"Skipping {tag}: predates the documentation site", flush=True)
                continue
            source = sources / tag
            source.mkdir()
            archive = work / "source.tar"
            subprocess.run(["git", "archive", f"--output={archive}", commit], cwd=ROOT, check=True)
            subprocess.run(["tar", "-xf", str(archive), "-C", str(source)], check=True)
            print(f"Building {tag} ({commit[:8]})", flush=True)
            build_book(source, books / tag, tag, f"{SITE}{tag}/")
            supported.append(tag)
        versions = [*supported, "master"]
        print("Building master from the current checkout", flush=True)
        build_book(ROOT, books / "master", "master", f"{SITE}master/")
        latest = supported[0]
        build_book(sources / latest, books / "default", latest, SITE)
        pages = {version: {p.relative_to(books / version).as_posix()
                           for p in (books / version).rglob("*.html")} for version in versions}
        for version in versions:
            decorate(books / version, version, versions, pages)
        decorate(books / "default", latest, versions, pages)
        shutil.copytree(books / "default", destination)
        for version in versions:
            shutil.copytree(books / version, destination / version)
        legacy_redirects(destination, pages, latest)
        for name in ("version-selector.js", "version-selector.css"):
            shutil.copyfile(ROOT / "theme" / name, destination / name)
        print(f"Built {len(versions)} versions; default is {latest}: {destination}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest-dir", type=Path, default=ROOT / "target" / "doc-site")
    parser.add_argument("--releases-json", type=Path,
                        help="use a saved GitHub releases API response (for offline builds)")
    args = parser.parse_args()
    releases = json.loads(args.releases_json.read_text()) if args.releases_json else published_releases()
    build_site(args.dest_dir.resolve(), releases)


if __name__ == "__main__":
    main()
