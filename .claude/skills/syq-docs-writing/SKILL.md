---
name: syq-docs-writing
description: How to write and revise syq's user documentation (README.md and docs/, published with mdBook) - tone, how much detail each page holds, and where a behavior change is documented. Use when editing README.md or any file under docs/.
---

# Writing syq documentation

`docs/` is the source of the documentation site published with GitHub Pages
(mdBook, configured by `book.toml`). Every page must be listed in
`docs/SUMMARY.md`; `scripts/check-doc-links.py` checks links.

Write these documents directly and conversationally, in plain words; a reader
should not need project jargon such as "retained" or "the ordinary engine" to
follow them.

Match documentation detail to the page's job. Setup and task guides should
give a useful example, explain consequential choices, and link to reference
material. Reference pages hold option interactions and scripting contracts;
security pages explain trust boundaries. Algorithm mechanics and regression
histories usually belong in code, tests, or the PR description.

When adding behavior, revise the paragraph that owns it rather than appending
a new explanation everywhere it is mentioned. Read the surrounding section as
a new user: keep details that help them act or interpret a result. A fixed bug
does not automatically need a new paragraph. Avoid release-number history and
unmeasured tuning advice in guides; benchmark claims need linked evidence.

Use [the docs audit skill](../../../.agents/skills/syq-docs-audit/SKILL.md)
for requested editorial audits and during release preparation. An audit can
identify a product question without changing runtime behavior to simplify its
explanation.
