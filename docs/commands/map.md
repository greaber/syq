# syq map

List local source/destination pairs as NDJSON for `syq cp --mapping`. No destination
is contacted. For transformations and the record format, see
[Rename and reorganize](../mappings.md).

```sh
syq map --srcs-in photos > photos.ndjson
syq cp --mapping photos.ndjson -C photos --into archive
```

Named selectors must be relative to their source base; use `-C` or `--root` to
choose it. `--srcs-in` must be the sole selector. `--as` requires one named
selection and chooses its name within the future destination container.
A directory emits separate entries for its descendants. Names must be UTF-8.
Copy filters belong to the transformation or consuming `cp`, not to `map`.

All arguments and options follow. See [producer failures](../mappings.md#check-the-producer-before-copying)
before piping a transform directly into a copy.

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

