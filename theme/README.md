# syq documentation theme

As of 2026-09-05, docs and benchmarks share Open Sans headings and prose,
a blue Manrope syq wordmark, IBM Plex Mono commands and numbers, and white/dark
palettes. Main text is 20px. The same top navigation links both sites, while
the docs retain mdBook's compact sidebar and benchmarks keep their own layout.

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
anchor offsets. `docs.js` adds the current-site marker and moves the existing search, theme and
sidebar controls into the shared header, preserving mdBook listeners and shortcuts.
Print and edit links appear below the article; the duplicate title and GitHub
shortcut no longer need a separate toolbar row. Search opens only when requested.
The header is a supported partial; the full mdBook template and scripts remain
upstream so search, chapter navigation, keyboard shortcuts and code copying
continue to receive mdBook fixes. The built-in light/rust preferences use the
white palette; navy/coal/ayu use the matching dark palette. Auto follows the OS.

Use the mdBook version pinned in `.github/workflows/pages.yml`, run
`mdbook build` and `python3 scripts/check-doc-links.py`, and check rendered
fonts, desktop/phone layouts, both color schemes, search, mobile chapter menus,
code copying, anchor offsets and JavaScript-disabled navigation. Theme assets
are included in the Pages trigger and mdBook's preview watch list.

The font stylesheet uses mdBook's resource helper to resolve hashed font
filenames. syq-bench embeds the same resources as data URIs. Do not replace the
resource placeholders with literal paths: those break mdBook's asset hashing.

With JavaScript enabled, the original toolbar and hover placeholder are hidden,
and the page margin no longer compensates for that placeholder. Header controls
remain fixed while scrolling. Without JavaScript, the native toolbar remains
available below the header for sidebar and page links; its sticky offset still
overrides mdBook's default. Mobile chapter drawers start below the shared header.

When upgrading mdBook, check 320/390/620/760/820/1440px layouts, navigation and
control overlap, initial headings and fragment offsets, search via click and `/`,
themes via mouse/keyboard, chapter toggling, scrolled reload, print/edit links,
and navigation without JavaScript. The adapter moves upstream nodes rather than
forking the book template or replacing the control implementations.

The oversized side-of-page chapter arrows are hidden; sidebar links and the
end-of-page navigation provide the chapter routes.
