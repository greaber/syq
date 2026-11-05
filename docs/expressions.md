# Select entries with expressions

Use `--where` to select files and other non-directory source entries in `map`
and `cp`, and `--copy-if` to decide whether a copy may update its destination.
Both take a quoted expression:

```sh
# Copy regular files between 1 MiB and 100 MiB.
syq cp --srcs-in project --into backup \
  --where 'src.kind = "file" and src.size between 1MiB and 100MiB'

# Add missing entries and update files whose source is newer.
syq cp --srcs-in project --into backup \
  --copy-if 'not dst.exists or src.mtime > dst.mtime'

# Select recent JPEGs, using the existing ignore rules too.
syq cp --srcs-in photos --into archive --ignore-from .gitignore \
  --where 'src.name matches "(?i)\\.jpe?g$" and src.mtime >= now - 7d'
```

`--where` works with local, SSH, and S3 sources. `--copy-if` is only for
`cp`, and can't be combined with `--in-place`. Neither applies to descriptor
or pipe copies.

## Selection and updates

Use `--where` to choose files by their own metadata, and `--copy-if` to
compare each file with what is already at its destination. `--where` sees
only `src` fields; `--copy-if` also sees `dst`, the destination that placement
or a mapping chooses. An entry is copied only when both expressions are true
and the `--if-exists` policy allows it, and unchanged files are still skipped.
Each option can be given once; combine conditions with `and` and `or`.

`--where` doesn't filter directories: they are copied even when none of their
contents are selected. A false `--copy-if` skips only a directory's own
metadata, not its contents. To skip a whole subtree without reading it, use
[ignore rules](reference.md#ignoring-paths) instead; an expression can't
re-include an ignored path.

With `--prune`, a source entry an expression excludes still protects its
destination counterpart, and destination entries with no source are still
pruned. An error during evaluation, such as division by zero or a failed
metadata read, fails the copy and prevents pruning; files already copied
stay. Mistakes in syntax, field names and types are reported before copying
starts.

## Fields

Prefix every field with `src.` or `dst.`. Metadata describes the entry
itself: a symlink found inside a directory is not followed.

| Field | Type and meaning |
|---|---|
| `path` | Source path relative to its selected scan root. Destination path relative to the `--into` container or the tree placed with `--as`. A root entry, including a single file placed with `--as`, uses its basename. With `--mapping`, `src.path` is the mapping's source path relative to `-C`. |
| `name` | Last path component |
| `extension` | Text after the last dot in `name`, without the dot; empty for extensionless names and a leading dot alone |
| `exists` | Whether the entry exists; always true for a scanned source |
| `kind` | `"file"`, `"dir"`, `"symlink"`, `"fifo"`, `"socket"`, `"char"`, `"block"`, or `"other"` |
| `size` | Size in bytes; for anything but a regular file, the value depends on the platform |
| `mtime` | Filesystem modification timestamp, stored in syq object metadata on S3; `null` when unavailable |
| `s3_last_modified` | S3 service modification timestamp; `null` on filesystem endpoints |
| `ctime` | Filesystem status-change timestamp, not creation time |
| `mode` | Permission and special bits as an integer; excludes the entry type |
| `uid`, `gid` | Numeric owner and group IDs |
| `device`, `inode`, `nlink` | Filesystem device, inode, and link count |
| `link_target` | Raw symlink target text on filesystem endpoints; `null` for other entries |

Names and paths preserve raw filename bytes. String equality is exact and
case-sensitive. `src.name = "*.jpg"` tests for that literal name; use `glob`
for a pattern.

For an absent destination, `exists` is false, path fields still describe its
placement, and metadata fields are `null`. S3 has no `ctime`, device, inode,
link count, or exposed link-target field. Permissions and ownership are
available only when the object carries syq metadata. Use
`coalesce(src.mtime, src.s3_last_modified)` to prefer the stored time and fall
back to the service's time, as downloads do.

On S3, path, name, extension, size, and `s3_last_modified` come from the
listing, and other fields need a request for each object, so put conditions
on the listed fields first.

Use `is null`, `is not null`, or `coalesce(value, fallback)` for unavailable
metadata. Equality treats `null` as a distinct value, but ordering,
arithmetic, and pattern matching on `null` are errors.

```text
src.uid is not null and src.uid = 1000
not dst.exists or src.size > dst.size
coalesce(dst.size, 0B) < src.size
src.mode & 0o111 != 0
```

## Values and operators

| Form | Meaning |
|---|---|
| `true`, `false`, `null` | Boolean and unavailable values |
| `123`, `0o640`, `0xff` | Decimal, octal, and hexadecimal integers |
| `1B`, `2KiB`, `1.5MiB`, `3GiB`, `1TiB` | Byte quantities with binary units |
| `1kB`, `2MB`, `3GB`, `1TB` | Byte quantities with decimal units (`KB` also accepted) |
| `1ns`, `2us`, `3ms`, `4s`, `5m`, `6h`, `7d`, `2w` | Durations; a day is 24 hours and a week is seven days |
| `now` | The time the command started, the same for every entry |
| `timestamp("2026-09-01T00:00:00Z")` | RFC 3339 timestamp with an explicit timezone |
| `"text"`, `'text'` | Strings; escapes are `\\`, `\"`, `\'`, `\n`, `\r`, `\t`, and `\xNN` for a byte |
| `=`, `==`, `!=`, `<>`, `<`, `<=`, `>`, `>=` | Exact equality, inequality, and ordering |
| `and`, `or`, `not` | Boolean operations |
| `+`, `-`, `*`, `/`, `%` | Checked arithmetic; integer division truncates toward zero |
| `&`, `^`, `\|` | Integer bitwise operations |
| `value in [a, b]` | Membership; parentheses may replace the brackets |
| `value between low and high` | Inclusive bounds |
| `value glob "pattern"` | Whole-path glob: `*` and `?` stay within a component; `**` can cross components |
| `value matches "pattern"`, `value =~ "pattern"` | Rust regex search; use `^` and `$` to anchor it |
| `if(condition, yes, no)` | Conditional value |
| `coalesce(value, fallback)` | Use the fallback only when the first value is `null` |

`not in`, `not between`, `not glob`, and `not matches` negate those operations.
Patterns and timestamp arguments must be quoted literals. Regex backslashes
need a string escape, as in the JPEG example above.

Types must agree: compare a size with `10B`, not `10` or `"10B"`. Subtracting
timestamps gives a duration, and adding a duration to a timestamp shifts it.
Arithmetic and bitwise operators bind most tightly, then comparisons, then
`not`, `and` and `or`; use parentheses to group conditions otherwise. `and`,
`or`, `if` and `coalesce` evaluate only what they need, so put an availability
check before a condition that needs the value.

Expressions can't run commands, read other files, or look at other entries.
To select using external data, generate a [mapping](mappings.md) with a
program.
