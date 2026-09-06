# Persistent data connection probe

2026-09-06. This short follow-up measures reuse of an existing SSH login for a
data worker. **Persistence is on for both copies.** It does not replace the
[primary persistence-off comparison](ssh-push-benchmark-cold.md) or establish
an advantage over rsync.

| Variant | Whole command | Control ready | Data worker ready |
| --- | ---: | ---: | ---: |
| Released syq `f4aee996` | 5.479 s | 0.00 s | 3.34 s |
| Data login reuse at `1f6a12c` | 2.862 s | 0.00 s | 0.60 s |

The elapsed saving is 2.617 seconds (47.8%) in this single A/B pair. The
2.74-second reduction in data-worker startup supports the intended mechanism:
the worker opens another channel on the persistent SSH login instead of
establishing another login. Transfer rate is not the main explanation for this
300 KiB copy. These are phase diagnostics, not disjoint intervals to sum.

Both variants copy the same generated 300 files of 1 KiB from the Mac to the
Linux endpoint. That file count exceeds the native control-only shortcut's
limit, so the copy starts a data worker. Both use explicit `-j 1`, `--no-tcp`,
`--preserve=permissions`, and `--stats`. Explicit workers also disable the
candidate's separate automatic one-worker selection change; the only applicable
runtime difference from the release is persistent data login reuse.

Each variant gets its own private persistence scope. An untimed tiny
control-only copy warms that variant's SSH login first. Both measured control
connections are therefore already ready. Each timed copy uses a fresh empty
destination, the same SSH keepalive settings (15 seconds, count 3), and a
matching native Linux helper. The monotonic timer encloses the whole command.
Both copies pass full SHA-256 verification outside the timer. No rsync sample
is included, because this probe asks whether the change helps an already
persistent syq session.

The [raw measurements](ssh-persistent-data-probe.csv) retain both observations.
An initial harness attempt used six workers and incorrectly required every
worker to connect before this tiny copy finished. Its before copy verified,
then the harness assertion stopped the pair. The corrected one-worker probe
above completed both variants. All private scopes and generated remote scratch
were removed; the user's persistence setting and sessions were preserved.

This evidence gives a reason to consider the narrowly scoped reuse change
again. It remains withdrawn from the benchmark-fix branch; this probe does not
reinstate it or justify changing worker defaults. More than one pair would be
needed to estimate its typical benefit reliably.
