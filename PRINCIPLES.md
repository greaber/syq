# Project principles

This file records core principles of syq that the maintainer has decided.
Code, tests, and documentation should follow them. Where the code on `master`
does not, that is a bug to fix, not a new exception.

Some principles are fixed properties of syq. Others protect something important
without freezing it: the behavior may change, but only after explicit discussion
with the maintainer.

Only the maintainer decides what belongs here. A contributor or agent may
propose an addition or change in a pull request, and should say so at the top
of the pull request so it is reviewed as a decision rather than as routine
editing. If a task seems to require breaking a principle, raise that before
implementing it.

## File operations have no incidental write requirements

Copying works with read-only source data. Removal works on a completely full
filesystem, which is often why someone is removing files.

An unwritable home directory or cache must not block copying or removal merely
because syq cannot save optional state. Caches, tuning information, completion
caches, and optional resume or recovery records can improve these operations,
but failures to read or write that state must not prevent them from succeeding.

Syq may use a few small temporary files or sockets under `TMPDIR`, or `/tmp`
when it is unset. Keep these requirements small.

Features that inherently need installation, authorization state, or durable
logs can require writes outside the files being copied or removed. Their
documentation must explain what they write, where, and which locations must
be writable. Required security state must not be silently skipped when writing
it fails.

Why: optional bookkeeping and performance improvements should never prevent
useful file operations. Features with necessary write requirements should make
those requirements clear.

## Startup latency and throughput are core

Speed is a central reason to use syq. A change that could make startup or
transfers slower needs explicit discussion first. When it is unclear whether a
change affects performance, measure it or discuss it rather than assuming it
does not. Behavior that costs performance for some other benefit is opt-in
unless the maintainer decides otherwise.

## Security guarantees change only by explicit decision

[docs/security.md](docs/security.md) describes the protections syq gives. They
can change, but a change that weakens them, including in rare cases, needs
explicit discussion first. Syq never does more than an approval or grant
allows.

## The selected data route stays fixed

TCP may fall back to SSH between the same endpoints, but a failure must never
silently relay file data through the invoking or authorizing machine. Relaying
requires an explicit route choice.

Why: a user who chose a direct route did not choose to send their data through
another machine, with that machine's bandwidth, cost, and exposure.

## Copy failures are visible

An incomplete or truncated result must never look successful.

Why: people rely on a destination that syq reports as complete.
