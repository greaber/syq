# syq documentation theme

As of 2026-09-05, docs and benchmarks share Open Sans headings and prose,
a blue Manrope syq wordmark, IBM Plex Mono commands and numbers, and white/dark
palettes. Main text is 20px. The same top navigation links both sites, while
the docs retain mdBook's compact sidebar and benchmarks keep their own layout.

The shared UI toolkit is inventoried in site-ui.json. Every mapped file must
remain byte-for-byte identical to the syq-bench copy, including fonts/licenses.
It owns branding, homepage buttons, sidebars, and Contents/Theme/Search controls.
Both sidebars use 15px links, 16px headings, 24px left and 12px right padding.

Compare from either repo before review (arguments are toolkit directories):

    python3 theme/check-site-ui.py /path/to/syq-bench-task/src/syq_bench theme

See site/BRANDING.md in syq-bench for the inventory and copy workflow.
Each site builds independently from its committed toolkit.

docs.css and docs.js adapt mdBook. Native search and theme handlers remain
behind the shared controls. Print/edit actions stay below the article. The
toolkit replaces the toggle and resize handle and reconciles native touch
gestures; mdBook still generates chapters, in-page links and search results.
Widths and desktop visibility persist when storage is available. Drag or use
arrow keys to resize; Home/double-click resets width. Mobile drawer behavior
and animations match benchmarks, including reduced-motion support.
System/Light/Dark replace the redundant mdBook palette names in the visible UI.
The native toolbar remains available when JavaScript is disabled.

Build with pinned mdBook and run the source link checker. Check both sites at
320/390/620/760/820/1440px: resizing, persistence, navigation, keyboard controls,
search hits/misses, themes, code copying, reduced motion and no-JS fallback.
Resize arrow keys must not trigger mdBook chapter navigation.

The font stylesheet uses mdBook's resource helper to resolve hashed font
filenames. syq-bench embeds the same resources as data URIs. Do not replace the
resource placeholders with literal paths: those break mdBook's asset hashing.

The oversized side-of-page chapter arrows are hidden; sidebar links and the
end-of-page navigation provide the chapter routes.

Documentation walkthroughs use semantic HTML styled in `docs.css`, keeping text
selectable and readable without JavaScript, in both palettes and on narrow
screens. Prefer a compact example or flow diagram where it replaces a long
explanation; keep detailed benchmark methodology on the speed page rather than
the installation path. The benchmark figure is a condensed real local quick
run (release-profile syq `9e73649`, three trials, 1 × 64 MiB and 1,024 × 8 KiB;
original mean times: syq 0.095/0.167 s, rsync 0.118/0.118 s, cp 0.049/0.052 s).
The figure shows arithmetic mean trial speeds in decimal MB/s, calculated
from the individual recorded durations rather than those rounded mean times. It illustrates
the workflow, not comparative performance evidence. The choices now show automatic
sizing; the example speeds still come from that fixed-size sample: the run shared the machine
with other work. Preserve the example caption if updating its presentation.

Anchor navigation scrolls smoothly, matching benchmarks. The reduced-motion
preference disables this animation. Both sites use 20px Open Sans main prose
and compact 15px Open Sans navigation with a 300px default sidebar width;
their content layouts remain independent.

The docs and benchmark homepages use the shared landing-title styles: a large
blue Manrope wordmark above an Open Sans title. This adds character to the
homepages while retaining the compact navigation and normal article headings.
The docs homepage preserves its copy-files-with-syq fragment for existing links.

The homepage leads with fast, programmable file operations and a short
description of copying, reorganizing, removing, resuming and automation.
Shared landing-actions buttons offer installation, benchmarks, sending files
home, server-to-server copies and programmable file placement. Quickstart
examples follow under Try a copy.

## SDK documentation

The SDK guide, API reference and compatibility pages in docs/ use mdBook
includes to render the sources in sdk/. Edit those source files so the web
pages and packaged SDK documentation stay in sync. Links in included sources
use full documentation URLs so they also work on GitHub and PyPI. book.toml
watches sdk/ when serving the book locally.
