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
  N processes, N ssh handshakes, no shared scan, no parallelism, no
  preflight conflict checking, no aggregate result.
- **Rename propagation via a temporary hardlink working copy**
  ([Lincoln Loop](https://lincolnloop.com/blog/detecting-file-moves-renames-rsync/)):
  `cp -rlp` the tree, reorganize the copy, then sync *both* trees with
  `rsync -aH --no-inc-recursive` so the receiver reconstructs the new
  layout from hardlink identity. Documented costs: a temporary duplicate
  tree, `-H` overhead, incremental recursion disabled, hardlink support
  required on both ends, the original tree frozen during reorganization,
  manual cleanup afterwards.
- **Photo tools ship the farm workflow as a feature.**
  [`photo_reorganize`](https://github.com/jpdaigle/photo_reorganize)
  builds a date-layout hardlink farm *expressly* so that plain rsync can
  mirror a restructured view of a photo collection;
  [phockup](https://github.com/ivandokov/phockup) and
  [PhotoSort](https://github.com/0xCCF4/PhotoSort) offer
  move/copy/hardlink placement actions. These are placement engines
  maintaining a permanent farm as an rsync adapter.
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

- **Cloud and object-store destinations.** rclone ignores symlinks by
  default; its `--links`/`--copy-links` semantics and `.rclonelink`
  marker objects are recurring support topics
  ([1](https://forum.rclone.org/t/rclone-not-handling-symlinks-as-symlinks/48369),
  [2](https://forum.rclone.org/t/problem-with-symlinks-and-links/23840)).
  Object stores have no symlink concept and generally no rename
  primitive (a "rename" is a server-side copy), so a symlink farm cannot
  be expressed at the destination and dereferencing at upload is forced.
  The farm workaround degrades hardest exactly where placement must be
  final at upload time.
- **Global dereferencing is blunt.** Consuming a farm with `-L`
  dereferences *every* link, so a tree that itself contains symlinks
  that should arrive as symlinks cannot be expressed;
  `--copy-unsafe-links` heuristics mangle absolute or outward links.
- **Hardlink farms** additionally require a same-filesystem writable
  staging location and (for the rename-propagation trick) hardlink
  support on both ends.

## Reading

The adapter pattern is widespread, named, and tool-supported: people
build and maintain link farms *because* rsync-family tools have no
mapping input. That demonstrates demand for the underlying capability —
restructure while transferring, with delta/resume/verification — while
the documented costs (farm lifecycle and hygiene, duplicate staging
state, global-dereference hazards, per-pair invocation loops,
object-store impedance) are what a first-class mapping input would
remove. Whether a mapping *format* beats a farm for a given audience is
a separate product question tracked in the design discussion; this
survey establishes only that the problem is real and the incumbent
solutions are costly.

A forward-looking note on object stores: if syq ever grows
S3-compatible endpoints (an open strategic question with its own
constraints — no atomic rename, no native symlinks, different resume
and verification models; see `current-plans/rclone-pain-points.md`),
mapping input is the natural interface there, because the farm
workaround is not merely clunky but inexpressible at the destination
and re-placement after upload is a paid copy.
