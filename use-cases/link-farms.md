# Link farms as transfer adapters: evidence from the wild

Status: evidence survey, gathered by web search on 2026-09-01 while
evaluating a proposed `--mapping` input mode for syq (explicit
source→target manifests; design discussion in `current-plans/`, not yet a
product commitment). Recorded here because the evidence is durable even
though the proposal is not: it documents what people do *today* with
rsync-family tools when they need to restructure a tree while
transferring it, and what that costs them.

## The question

rsync (and syq today) can select files (`--files-from`) but cannot
*re-place* them: every transferred file keeps its source-relative path.
When people need "this source file should land at that different
destination path," what do they actually do, and does it hurt?

## The distinction that organizes the evidence

Link farms appear in two roles that must not be conflated:

- **Links as the product**: the symlinks or hardlinks are the point —
  a live view of files that stay canonical elsewhere. Editing the target
  updates the view; nothing is being transferred. This role is *not*
  evidence for a mapping-input feature; a copy would be strictly worse.
- **Links as a transfer adapter**: the farm exists only to express a
  source→destination mapping in the filesystem so that a sync tool,
  which has no mapping input, can consume it. The farm is scaffolding;
  the copy is the point. This role is direct evidence that mapping input
  is a missing feature of the transfer tool.

Some setups mix the roles (see the seedbox pipeline below).

## Evidence: links as a transfer adapter

- **`--files-from` cannot rename, and people hit the gap directly.**
  The standard documented workaround is a mapping file of
  source→destination pairs driving *one rsync invocation per pair*
  ([codestudy guide](https://www.codestudy.net/blog/using-rsync-to-rename-files-during-copying-with-files-from/),
  [LinuxQuestions thread](https://www.linuxquestions.org/questions/linux-general-1/looping-rsync-to-rename-files-at-destination-help-4175723362/)).
  This is a hand-rolled mapping manifest without a tool to consume it:
  N rsync processes with no shared scan, where parallelism, preflight
  conflict checking, and aggregate results must all be added externally
  (ssh setup can be amortized with connection multiplexing, and local
  copies have none, so the invocation overhead itself is the smaller
  cost).
- **Rename propagation via a temporary hardlink working copy**
  ([Lincoln Loop](https://lincolnloop.com/blog/detecting-file-moves-renames-rsync/)):
  `cp -rlp` the tree, reorganize the copy, then sync *both* trees with
  `rsync -aH --no-inc-recursive` so the receiver reconstructs the new
  layout from hardlink identity. Documented costs: a temporary duplicate
  tree, `-H` overhead, incremental recursion disabled, hardlink support
  required on both ends, the original tree frozen during reorganization,
  manual cleanup afterwards.
- **A photo tool ships the farm workflow as its documented purpose.**
  [`photo_reorganize`](https://github.com/jpdaigle/photo_reorganize)
  builds a date-layout hardlink farm *expressly* so that plain rsync can
  mirror a restructured view of a photo collection — direct adapter
  evidence. [phockup](https://github.com/ivandokov/phockup) and
  [PhotoSort](https://github.com/0xCCF4/PhotoSort) are weaker, indirect
  evidence: they are placement engines offering move/copy/hardlink
  actions, but their documentation does not describe maintaining a farm
  for a sync tool to consume.
- **Media pipelines chain placement-engine → farm → sync tool.**
  FileBot's rename actions include symlink and hardlink modes
  ([FileBot forum](https://www.filebot.net/forums/viewtopic.php?t=11758));
  seedbox setups such as
  [this rtorrent/deluge pipeline](https://gist.github.com/werrpy/a4ff72e9bc78da645f42e25eccbacd7b)
  hardlink completed torrents into a staging directory, FileBot-rename,
  upload with rclone, then unlink — with hand-rolled lock checks against
  concurrent runs and staging/active directory choreography. The *local*
  hardlinks are partly links-as-product (the torrent layout and the
  media layout must coexist on one disk for seeding), but the upload leg
  consumes the farm purely as a transfer adapter, and the lifecycle
  machinery around it is incidental complexity.

## Evidence: links as the product (not an argument for mapping input)

- **GNU Stow and dotfiles.** [Stow](https://www.gnu.org/software/stow/)
  calls itself a "symlink farm manager"; its dominant modern use is
  dotfiles kept canonical in a git repository and symlinked into `$HOME`
  (e.g. [this walkthrough](https://medium.com/quick-programming/how-i-use-gnu-stow-to-organize-my-dotfiles-in-git-d3281147e1c8)).
  There the live indirection is the feature — edit in the repo, the
  change is live — and no transfer tool is involved. What Stow *does*
  contribute to the mapping discussion is precedent for the claims
  model: it refuses to stow over a target it does not own
  ([manual](https://www.gnu.org/software/stow/manual/stow.html)), the
  same conflict discipline a mapping preflight enforces; and its need
  for a dedicated dangling-link checker (`chkstow --badlinks`) documents
  farm hygiene as a real ongoing cost even when links are wanted.
- **Seeding hardlinks** (the local half of the seedbox pattern above):
  two layouts sharing one copy of the data is deduplication as a
  feature, not a workaround.

## Evidence: where farm consumption breaks

- **Cloud and object-store destinations — for symlink *fidelity*, not
  placement.** rclone ignores symlinks by default; its
  `--links`/`--copy-links` semantics and `.rclonelink` marker objects
  are recurring support topics
  ([1](https://forum.rclone.org/t/rclone-not-handling-symlinks-as-symlinks/48369),
  [2](https://forum.rclone.org/t/problem-with-symlinks-and-links/23840)).
  Important scoping: this does *not* make a source-side farm unusable as
  an adapter — `rclone copy -L farm/ remote:` dereferences locally and
  the destination only ever sees plain objects
  ([rclone local backend](https://rclone.org/local/)). The forum pain is
  mostly about preserving symlinks in backups, a different problem. What
  most flat-namespace object-store backends add is that placement must
  be final at upload time (no rename primitive; a "rename" is a paid
  server-side copy — not categorical: S3 Express directory buckets have
  [RenameObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RenameObject.html),
  and hierarchical stores can rename atomically) — but the farm
  satisfies that via local dereference too, so object stores are not by
  themselves a farm-vs-mapping differentiator for ordinary placement.
- **Global dereferencing is blunt.** Consuming a farm with `-L`
  dereferences *every* link, so a tree that itself contains symlinks
  that should arrive as symlinks cannot be expressed;
  `--copy-unsafe-links` heuristics mangle absolute or outward links.
- **Hardlink farms** additionally require a same-filesystem writable
  staging location and (for the rename-propagation trick) hardlink
  support on both ends.

## Steelman: the case that no new tool is needed

Each adapter item re-examined with the strongest available argument that
the incumbent solution is actually fine.

- **Per-pair rsync loops**: for a one-shot migration you can also
  transfer with names unchanged and run a cheap rename pass at the
  destination afterwards — renames are nearly free locally, and rsync
  keeps its delta/resume for the bulk transfer. This works. What it
  cannot do is *converge*: on the next run rsync compares against the
  renamed destination, sees nothing matching, and retransfers
  everything. The steelman fully covers one-shot jobs; only recurring
  synchronization survives as demand.
- **Rename propagation to an existing mirror (Lincoln Loop)**: the
  steelman wins outright, and not only because the need is rare. The
  workaround's essential ingredient is destination-side content reuse —
  the receiver reconstructs the new layout from hardlink identity
  without retransfer. Mapping input as proposed does **not** provide
  that: syq would compare each source file against its (empty) new
  destination path and retransfer the tree, because the content at the
  old destination paths is invisible without a rename-detection or
  content-reuse feature. For this scenario the incumbent hack beats the
  proposed feature.
- **Photo farm tools**: the farm is cheap (hardlinks), the workflow is
  two cron lines, and the farm doubles as a browsable local
  date-organized view — partially links-as-product, which mapping input
  does not replace. The farm arguably dominates unless the source host
  cannot hold or reach a staging location (remote, no shell) or the
  permanent farm's drift and hygiene costs bite; a filesystem without
  hardlinks (FAT/exFAT cards) only rules out the hardlink variant, since
  a symlink farm on another filesystem consumed with `-L` still works.
- **Seedbox pipelines**: most such users need the local media-layout
  view anyway (Plex reads local or mounted files), so the farm exists
  regardless and mapping input adds little. The exception is
  cloud-serving setups like the surveyed gist, which unlink the farm
  after upload — there it was pure transfer scaffolding.
- **rclone symlink threads**: much of the forum pain is about symlink
  *fidelity in backups* (a different problem), and for the adapter use
  `rclone copy -L farm/` works: the links are dereferenced locally and
  the destination sees only plain objects. This item is weaker as
  mapping evidence than it first appears; what survives of it is only
  the global-dereference bluntness (symlink-bearing content) that
  applies everywhere, not an object-store-specific gap.

## Reading

The adapter pattern is widespread, named, and tool-supported: people
build and maintain link farms *because* rsync-family tools have no
mapping input, and the documented costs (farm lifecycle and hygiene,
duplicate staging state, global-dereference hazards, per-pair
invocation loops) are real. After the steelman, though, the demand is
narrower than a first reading suggests: one-shot migrations are
adequately served by transfer-then-rename or a throwaway farm, mirror
rename propagation is *better* served by the hardlink trick than by
mapping input v1, and the photo/media farms partly pay for themselves
as local views. What survives as the demand profile for mapping input:
**recurring convergent restructure-transfer** where the destination
layout is the authoritative one and a farm is unavailable or
unattractive — a remote source host with no writable staging location
or shell access (a farm can otherwise live in any writable directory
and point across filesystems, including into read-only content),
symlink-bearing content, and fragments from distributed producers.
Whether that profile contains a
killer example is the open product question tracked in the design
discussion; this survey establishes that the problem is real, the
incumbents are costly, and the honest bar for the feature is the
narrowed profile, not the broad pattern.

A forward-looking note on object stores: if syq ever grows
S3-compatible endpoints (an open strategic question with its own
constraints — no atomic rename on most flat-namespace backends, no
native symlinks, different resume
and verification models; see `current-plans/rclone-pain-points.md`),
mapping input remains the natural *interface* there — placement must
usually be final at upload time since re-placement is a paid
server-side copy on most backends —
but a local farm consumed with dereferencing serves ordinary placement
at object stores too, so the argument for syq there rests on the same
residual differentiators as elsewhere plus whatever the endpoint itself
adds (convergence semantics, verification, exact accounting), not on
farms being unusable.
