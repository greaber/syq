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

## Copying and removing need write access only where they change files

Copying and removing files, whether through `syq cp`, `syq rsync`, or `syq rm`,
need write access only where they change files: for a copy, the destination
files and directories it creates, including their partial files; for a removal,
the files it removes. They work with read-only source data and with an
unwritable home directory or cache on every machine involved. Removal also works
on a completely full filesystem, which is often why someone is removing files.

Syq may read and write other state, such as the tuning cache, resume and
recovery records, and completion caches, to help performance, including for the
current operation. That state is optional: when syq cannot read or write it,
copying and removal still succeed.

Two exceptions are accepted. Installing a missing SSH helper needs somewhere
writable on the server. The helper has to live somewhere, and syq cannot assume
a writable temporary directory either. When the server's home is unwritable,
install syq there separately and use `--syq-path` or `--no-bootstrap`.

Copies also need a writable temporary directory, `TMPDIR` or else `/tmp`, on
each machine that reads or writes files. Syq keeps a private socket there so
its processes can share the files and directories a copy has opened. This is
tolerated for practical reasons rather than required: removing it would mean
changing how those processes find each other, which was not worth the work
while no one needed it (September 2026).

Why: this state exists to make syq faster. It should never be the reason a
copy or removal fails.

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
