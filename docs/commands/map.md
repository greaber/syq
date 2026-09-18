# syq map

Print local source/destination pairs as NDJSON for `syq cp --mapping`:

```sh
syq map --srcs-in photos > photos.ndjson
syq cp --mapping photos.ndjson -C photos --into archive
```

See [Rename and reorganize](../mappings.md) for selection rules, transformations,
and the record format.

<!-- CLI: map -->
```text
syq map [OPTIONS] PATH...
syq map [OPTIONS] --srcs-in DIR
```

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `-C, --cwd <DIR>` | Resolve relative source selectors from DIR |
| `--root <DIR>` | Resolve source selectors beneath DIR and refuse any escape |
| `--follow` | Follow symlinks in all directly supplied filesystem paths |
| `--follow-src` | Follow symlinks in directly supplied source paths |
| `--src <PATH>` | Select a named source object; attach =PATH when it begins with `-` (repeatable) |
| `--srcs-in <DIR>` | Select a directory's contents; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dir <PATH>` | Select a named non-directory source object; attach =PATH when it begins with `-` (repeatable) |
| `--src-dir <DIR>` | Select a named source directory; attach =DIR when it begins with `-` (repeatable) |
| `--src-non-dirs <PATH>...` | Select several named non-directory source objects |
| `--src-dirs <DIR>...` | Select several named source directories |
| `--srcs <PATH>...` | Select several named source objects |
| `[PATH]...` | Named source objects (shorthand for --src) |

## Destination placement

| Argument / option | Meaning |
|---|---|
| `--as <PATH>` | Emit the single selected root at PATH, relative to the future destination container; PATH may be nested |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |

<!-- /CLI -->
