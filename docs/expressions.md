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

`--where` works with local, SSH, and S3 sources in both commands. `--copy-if`
is available only for `cp`. Neither applies to descriptor or pipe copies.

## Selection and updates

`--where` accepts only `src` fields. `--copy-if` accepts both `src` and `dst`:
`dst` names the destination chosen by the copy's placement or mapping. An
entry is copied only when both options pass and existing policies such as
`--if-exists=keep` allow it. Each option can be given once; combine conditions
with `and` and `or`. A true expression does not force a rewrite: the copy's
usual comparison still skips unchanged files.

`--where` does not filter directories: they are copied as usual, even when
none of their contents are selected, and `map --where` always emits their
records. Metadata used by the expression is added to `map` records only when
requested with `--include`. For a directory, a false `--copy-if` result skips
only its own metadata, not its contents. On S3, `--where` never filters
directory-marker objects, but `--copy-if` can skip them.

Use [ignore rules](reference.md#ignoring-paths) to stop traversal of a subtree.
An expression cannot re-include an ignored path. With `--prune`, excluded
source entries still protect their destination counterparts. Destination-only
entries remain eligible for pruning even when an expression selects no files.

`--dry-run` uses the same expressions. Invalid syntax, unknown fields, and
incompatible types fail before copying starts. Evaluation errors, including
division by zero and failed metadata reads, fail the copy and prevent pruning;
files already completed can remain.

`--copy-if` cannot combine with `--in-place`.

## Fields

Prefix every field with `src.` or `dst.`. All filesystem metadata describes
the selected entry; recursively discovered symlinks are not followed.

| Field | Type and meaning |
|---|---|
| `path` | Source path relative to its selected scan root. Destination path relative to the `--into` container or the tree placed with `--as`. A root entry, including a single file placed with `--as`, uses its basename. With `--mapping`, `src.path` is the mapping's source path relative to `-C`. |
| `name` | Last path component |
| `extension` | Text after the last dot in `name`, without the dot; empty for extensionless names and a leading dot alone |
| `exists` | Whether the entry exists; always true for a scanned source |
| `kind` | `"file"`, `"dir"`, `"symlink"`, `"fifo"`, `"socket"`, `"char"`, `"block"`, or `"other"` |
| `size` | Entry size in bytes; regular-file length. Sizes of other filesystem entry types are platform-dependent. |
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
listing; other fields need a request for each object. Put those cheap
conditions first, so that an object they reject needs no extra request.

Use `is null`, `is not null`, or `coalesce(value, fallback)` for unavailable
metadata. Equality treats `null` as a distinct value. Ordering, arithmetic,
and pattern matching on `null` fail. Metadata read errors are reported as
errors, never converted to `null`.

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
| `now` | One fixed timestamp for this coordinator invocation |
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
timestamps yields a duration, and adding a duration to a timestamp shifts it.
Arithmetic and bitwise operators bind more tightly than comparisons, which
bind more tightly than `not`, then `and`, then `or`; use parentheses to group
conditions otherwise. `and` and `or` evaluate left to right and stop as soon as the
result is known, and `if` and `coalesce` evaluate only the needed branch, so
put an availability check before a condition that needs the value.

Expressions cannot execute commands, read arbitrary files, or query other
entries. For collection-wide selection or external data, generate a
[mapping](mappings.md) with a program.
