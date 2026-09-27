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

## Copying and removing write little outside the files they change

Copying and removing files, whether through `syq cp`, `syq rsync`, or `syq rm`,
write where they change files: for a copy, the destination files and
directories it creates, including their partial files; for a removal, the files
it removes. They work with read-only source data and with an unwritable home
directory or cache on every machine involved. Removal also works on a
completely full filesystem, which is often why someone is removing files.

Beyond that, syq may need a few small files, such as local sockets, in the
temporary directory: `TMPDIR` when it is set, otherwise `/tmp`. Syq keeps this
to a minimum.

Syq may also read and write optional state, such as the tuning cache, resume
and recovery records, and completion caches, to help performance. When syq
cannot read or write it, copying and removal still succeed.

Any other write requirement is discussed with the maintainer first and recorded
here. The accepted one is installing a missing SSH helper, which needs a
durable writable location on the server; the temporary directory is not a
lasting place for it. When the server's home is unwritable, install syq there
separately and use `--syq-path` or `--no-bootstrap`.

Why: the temporary directory is the conventional place for a program's
short-lived files, so a little space there is unsurprising. Caches and records
exist to make syq faster and should never be the reason a copy or removal
fails.

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
