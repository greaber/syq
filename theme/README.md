# syq documentation theme

As of 2026-09-05, the docs use the visual design established by syq-bench:
paper and cerulean, Manrope headings and navigation, Newsreader prose, and
IBM Plex Mono commands and numbers. The same header links both sites.

The shared source lives in syq-bench. Keep these copies byte-for-byte identical:

| syq-bench | syq |
| --- | --- |
| `src/syq_bench/brand.css` | `theme/brand.css` |
| `src/syq_bench/site-nav.html` | `theme/header.hbs` |
| `src/syq_bench/fonts/` including licenses | `theme/fonts/` |

See `site/BRANDING.md` in syq-bench for the copy and comparison commands.
Prepare paired task worktrees and pull requests for shared edits. Each repo
keeps its own committed assets and builds independently; neither site fetches
styles or fonts from the other at build time or in the browser.

`docs.css` is the mdBook adapter: prose, code, tables, sidebar, toolbar and
anchor offsets. `docs.js` adds the current-site marker and sidebar label.
The header is a supported partial; the full mdBook template and scripts remain
upstream so search, chapter navigation, keyboard shortcuts and code copying
continue to receive mdBook fixes. The built-in light/rust preferences use the
paper palette; navy/coal/ayu use the matching dark palette. Auto follows the OS.

Use the mdBook version pinned in `.github/workflows/pages.yml`, run
`mdbook build` and `python3 scripts/check-doc-links.py`, and check rendered
fonts, desktop/phone layouts, both color schemes, search, mobile chapter menus,
code copying, anchor offsets and JavaScript-disabled navigation. Theme assets
are included in the Pages trigger and mdBook's preview watch list.

The font stylesheet uses mdBook's resource helper to resolve hashed font
filenames. syq-bench embeds the same resources as data URIs. Do not replace the
resource placeholders with literal paths: those break mdBook's asset hashing.
