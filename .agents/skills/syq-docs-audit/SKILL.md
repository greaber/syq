---
name: syq-docs-audit
description: Audit syq documentation for user focus, excess detail, duplication, and unsupported claims. Use for requested editorial audits and during syq release preparation.
---

# Audit syq documentation

Read repository `AGENTS.md` and current task notes first; use its worktree,
commit, and review workflow. This skill does not authorize a release.

Treat the docs as a guide to useful behavior, not an inventory of implementation
facts. Start with README, the sidebar, and setup, then read affected task guides
and references, including the Python sources included by mdBook. For a release,
inspect documentation changes since the previous release and read their
surrounding sections. Reuse an audit recorded for the same content; review
subsequent changes rather than repeating it mechanically.

For each section, identify what the reader is trying to do. Guides stay lean
and do not overexplain: keep the instructions, examples, meaningful tradeoffs,
and limitations readers need to choose or use the feature, and link to the
reference for the rest. Reference pages describe semantics: what an option
does and how options interact, observable behavior and its conditions,
contracts such as machine output, limits a user will hit, and consequences;
they may be long. Link
security consequences to the relevant security section. No page, reference
included, explains how syq implements a behavior (algorithms, internal
ordering, batching, buffer sizes, scheduling), why it was designed that way,
or the performance trade-offs of internal choices; readers who want that can
read the code. Keep a performance fact only when it changes what a user should
choose, stated as a consequence. Also delete patch histories, defensive
explanations of ordinary behavior, repeated material, and unsupported tuning
advice. Moving every excess paragraph into reference is not a substitute for
editing it, and only semantics belong there. Shorten by removing unnecessary
ideas, not by stripping sentences into terse fragments. Read the result as
connected prose: explain how an instruction relates to the reader's task
instead of stacking isolated facts or command names.

Revise the existing explanation when a feature changes. Do not turn each bug fix
or edge case into another paragraph. Prefer a brief introduction with a link over
restating the reference on setup pages. Avoid specific syq versions in guides
unless a reader needs one to take an upgrade action.

Check examples and claims against code and measured evidence. Keep benchmark
workloads, source links, and important qualifications with their numbers; do not
present another benchmark tool's results as quick-script output. A favorable
measured example is useful when its context is clear.

If simplifying a passage raises a runtime safety or product question, investigate
and report it separately. Do not silently weaken a guarantee, change an interface,
or remove a necessary warning to shorten the docs. Make supported editorial fixes
without waiting for approval; ask about unresolved choices that materially change
behavior or leave the release documentation incorrect.

Build the book and check links, included SDK pages, and existing published
anchors. Preserve URLs when moving material. Inspect changed visuals at desktop
and phone widths in light and dark themes. Provide a browser preview for an
editorial review, following the current task's preview setup where available.

Report the edited SHA, principal cuts or moves, verification, preview, and any
remaining decisions. Keep only brief active state in `current-plans/`; do not add
an audit report, benchmark dump, or editorial checklist to the user docs. A release
audit does not impose an extra approval step when there is no unresolved decision.
