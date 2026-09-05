# Copy files

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Existing files are updated when
needed; unrelated files stay.

## See where files go

A named directory brings its name along. `--srcs-in` copies its contents;
`--as` chooses an exact destination name.

<div class="copy-demo" data-examples="assets/copy-examples.json">
  <div class="copy-demo-controls" hidden></div>
  <pre class="copy-demo-command"><code>syq cp project --to server --into /backup</code></pre>
  <p class="copy-demo-description" aria-live="polite">Copies project into /backup/project on server. Existing files outside that directory stay.</p>
  <p class="copy-demo-reset">Each example starts from the same files shown under Before.</p>
  <div class="copy-demo-trees">
    <section class="copy-demo-source" aria-label="Source on your machine">
      <h3>Your machine</h3>
      <pre>project/
├── index.html
└── images/
    └── logo.svg</pre>
    </section>
    <section class="copy-demo-before" aria-label="Destination before copying">
      <h3>Server · Before</h3>
      <pre>/backup/
├── index.html (old)
└── notes.txt</pre>
    </section>
    <section class="copy-demo-after" aria-label="Destination after copying">
      <h3>Server · After</h3>
      <pre>/backup/
├── index.html (kept)
├── notes.txt (kept)
└── project/ (new)
    ├── index.html
    └── images/
        └── logo.svg</pre>
    </section>
  </div>
</div>

Note to rsync users: trailing slashes have no special significance in syq's
native commands. `syq rsync` keeps rsync's slash rules.

## Copy over the network

Use `--to` to send files, or `--from` to fetch them:

```sh
# Copy project to /backup/project on server.
syq cp project --to server --into /backup

# Fetch /data/a and /data/b from server into ./data/a and ./data/b here.
syq cp --from server -C /data --src a --src b --into ./data
```

`-C DIR` is shorthand for `--cwd DIR`: look for the source files in `DIR`.
In the second example, `/data` is on the server and `./data` is on your machine.

To use the default destination:

```sh
syq cp project --to server       # put project in your home directory on server
syq cp --from server project     # fetch project into your current directory
```

Endpoints use `[USER@]HOST[:PORT]`, for example `alice@server:2222`.
Enclose IPv6 addresses in brackets: `alice@[2001:db8::1]:2222`.
A colon in a native path is simply part of the path.

For two remote endpoints, see [Copy between servers](remote-to-remote.md).

## Choose a destination

| Option | Meaning |
|---|---|
| `--into DIR` | Put the selected names inside `DIR` |
| `--as PATH` | Copy one named source to exactly `PATH` |
| `--into-new DIR`, `--as-new PATH` | Also require the destination not to exist |
| `--into-existing DIR`, `--as-existing PATH` | Also require it to exist |

```sh
# Copy report.txt under a new name; refuse to overwrite an existing entry.
syq cp report.txt --as-new reports/final.txt
```

`--into` uses or creates a directory. `--as` can rename a directory too.
Sources that would collide at one destination are refused before copying.

## Preview changes

`--dry-run` previews a copy without changing the destination. On its own it
prints a summary; combine it with `-v` to list the planned changes by path:

```sh
syq cp --dry-run -v --srcs-in project --into backup
```

The summary shows where files would land, what would change, and how much
data may move. Copy data stays unchanged; a requested results file is still
written. The filesystem can change between preview and execution.

## Mirror a directory

`--prune` removes destination files that have no counterpart in the source:

```sh
syq cp --prune --max-delete 100 --srcs-in build --into-existing deploy
```

This updates `deploy` from `build`, then removes extras. Preview with
`--dry-run -v` first. If more than 100 removals are planned, none are performed
and the command exits 25.

Pruning stays inside the copied directories. Copying named directories `a`
and `b` into `backup` prunes `backup/a` and `backup/b`, leaving `backup/c` alone.
Ignored paths and files skipped by size limits are protected.

Scan errors prevent deletion. An interruption after deletion starts can leave
some extras removed. Do not prune while another copy is writing into the same
tree: its files and partials can be treated as extras.

## Ignoring paths

```sh
# Use the project's existing ignore rules.
syq cp --ignore-from .gitignore --srcs-in project --into backup

# Skip node_modules and object files.
syq cp --ignore node_modules --ignore '*.o' --srcs-in project --into backup
```

Patterns use gitignore syntax. Rules run in command-line order; the last
match wins. `!` re-includes a path.

| Pattern | Matches |
|---|---|
| `foo` | A file or directory named foo at any depth |
| `/foo` | foo at the source root |
| `foo/` | Directories named foo |
| `*` | Within one path component |
| `**` | Across path components |

Ignored directories are not scanned. To keep part of one, include the parent:

```sh
# Skip other logs, but copy logs/keep and its contents.
syq cp --ignore 'logs/*' --ignore '!logs/keep/' --srcs-in project --into backup
```

Ignored paths are also protected from pruning.

## Resume an interrupted copy

Rerun the same command. Completed files are skipped; partially copied files
reuse matching blocks. By default, syq writes a partial file beside the
destination and replaces the final file only when complete.

Do not run the same logical copy twice concurrently: the runs share partial
files. To abandon a copy, stop it and delete its hidden partial files from the
destination. They are named `.FILENAME.syq-part.ID`, beside the intended final
file; long names may be shortened or hashed. For example, a partial for
`video.mp4` is `.video.mp4.syq-part.ID`. Use `ls -a` to see it, then `rm --`
with its exact name. Keep partials belonging to copies still running.

## Check file contents

Syq normally skips files whose size and modification time match.
`--hash` checks contents even when those two attributes match:

```sh
syq cp --hash --srcs-in project --into backup
```

This changes how syq decides what needs copying. For larger network
copies, syq still compares blocks when size or modification time differs,
even without `--hash`, so it can reuse unchanged data. Local and small copies
may use faster paths instead.

Transferred data is always checked for corruption. For files being changed by
another program, stop the writer or copy a snapshot. No copy makes the whole
tree transactional or guarantees durability across power loss.

To compare without writing, use
[`syq rsync --syq-verify-only`](rsync-compat.md#compare-without-copying).

## Preserve metadata

Copy keeps modification times and copies symlinks as symlinks. Add other
metadata when needed:

```sh
syq cp --preserve=permissions,ownership project --into backup
```

`permissions` preserves modes; `ownership` requests numeric owner and group;
`specials` enables device, FIFO, and socket nodes. Ownership needs suitable
permissions on the destination. Hard links, ACLs, and xattrs are not preserved.

## Symlinks

A named symlink is copied as a link. Syq refuses to follow links in paths you
supply unless you ask it to:

| Option | Follow links in |
|---|---|
| `--follow-src` | Source paths |
| `--follow-dst` | Destination paths |
| `--follow` | Both, plus files named by options such as `--ignore-from` |

```sh
# Copy the directory current-project points to as backup/current-project.
syq cp --follow-src current-project --into backup
```

With `--as link`, the final link itself is replaced, even with `--follow-dst`.
Links found inside a directory are never followed. See the
[security explanation](security.md#filesystem-attacks).

## Keep sources inside a directory

`--root DIR` both sets the source directory and prevents selections from
escaping it:

```sh
# Copy /srv/data/reports and /srv/data/photos into backup.
syq cp --root /srv/data reports photos --into backup
```

Sources must be relative to that root. A selection such as `../private` is
refused; even with `--follow-src`, symlinks cannot lead outside the root.
Unlike `-C`, this is a boundary, not just a starting directory. It does not
constrain the destination.

## More options

`--src-file` and `--src-dir` require a non-directory or directory respectively.
Use `--min-size` and `--max-size` to select regular files by size.

For parallelism and bandwidth controls, see [Speed](speed.md). For scripts,
see [Automation results](automation.md). `syq cp --help` gives common examples;
`syq cp --help-all` lists every option.
