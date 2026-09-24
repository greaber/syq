# Select entries with expressions

Use `--where` to select source entries and `--copy-if` to decide whether an
entry may update its destination. Both take a quoted expression:

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

These options work with local, SSH, and S3 pathname copies. They do not apply
to descriptor or pipe copies. `syq map` does not accept them.

## Selection and updates

`--where` accepts only `src` fields. `--copy-if` accepts both `src` and `dst`:
`dst` always names the destination chosen by the copy's placement or mapping.
When both options are present, both must pass. Existing policies such as
`--only-new` also apply. Each expression option can be supplied once; combine
conditions with `and` and `or`.

A true expression allows the copy to proceed through its normal comparison.
It does not force a rewrite of an unchanged file. Use `--hash` when contents
must be compared even if size and modification time match.

Directories remain traversable regardless of their expression result. On
filesystem destinations they can still be created as containers, including
empty directories; source directory metadata is applied only when both
conditions pass. Existing directories that fail a condition keep their
metadata, apart from the effects of adding or removing children. New containers
use the receiver's default permissions, including its umask and inherited
setgid bit. Existing containers may be made writable while children are copied;
their previous permissions are then restored. S3 directory-marker objects are copied only when selected; keys beneath them are
considered independently.

To copy directory metadata while filtering files, select directories explicitly:

```sh
syq cp --srcs-in photos --into archive --preserve \
  --where 'src.kind = "dir" or (src.kind = "file" and src.extension = "jpg")'
```

Use [ignore rules](reference.md#ignoring-paths) to stop traversal of a subtree.
An expression cannot re-include an ignored path. With `--prune`, excluded
source entries still protect their destination counterparts. Destination-only
entries remain eligible for pruning even when an expression selects no files.

`--dry-run` uses the same expressions. Invalid syntax, unknown fields, and
incompatible types fail before copying starts. Evaluation errors, including
division by zero and failed metadata reads, fail the copy and prevent pruning;
files already completed can remain.

Conditions use observed metadata. They are not locks or atomic assertions
against concurrent changes. `--copy-if` cannot combine with `--inplace`: an
interrupted write could change destination metadata and make a retry skip an
incomplete file. The early capacity check for a fresh destination is skipped
with `--copy-if`, since the selected size is not yet known. Running out of space
still fails the copy, but some files may already have been copied.

For restricted remote copies, expressions are evaluated by the coordinator
as copy preferences. They do not add receiver-enforced restrictions to a signed
grant; the grant continues to enforce its destination scope and permissions.

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
| `mtime` | Modification timestamp, including nanoseconds when available |
| `ctime` | Filesystem status-change timestamp, not creation time |
| `mode` | Permission and special bits as an integer; excludes the entry type |
| `uid`, `gid` | Numeric owner and group IDs |
| `device`, `inode`, `nlink` | Filesystem device, inode, and link count |
| `link_target` | Raw symlink target text on filesystem endpoints; `null` for other entries |

Names and paths preserve raw filename bytes. String equality is exact and
case-sensitive. `src.name = "*.jpg"` tests for that literal name; use `glob`
for a pattern. Device, inode, and owner IDs have meaning within their host;
equal numbers on separate hosts do not establish a shared identity.

For an absent destination, `exists` is false, path fields still describe its
placement, and metadata fields are `null`. S3 has no `ctime`, device, inode,
link count, or exposed link-target field. Permissions and ownership are
available only when the object carries syq metadata. S3 `mtime` uses stored
source time when present, otherwise the provider's modification time.

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
Patterns and timestamp arguments must be quoted literals. Glob and regex
patterns are compiled once. Regex backslashes need a string escape, as in the
JPEG example above.

Types must agree: compare a size with `10B`, not `10` or `"10B"`. Subtracting
timestamps yields a duration; adding or subtracting a duration shifts a
timestamp. Sizes and durations can be multiplied or divided by integers;
dividing two sizes or two durations yields an integer. Decimal quantities must
resolve to whole bytes or nanoseconds. Overflow is an error.

From highest to lowest precedence: unary minus; multiplication/division/remainder;
addition/subtraction; bitwise `&`, then `^`, then `|`; comparisons and membership;
`not`; `and`; `or`. Parentheses override precedence. `and` and `or` evaluate
left to right and short-circuit. `if` and `coalesce` evaluate only the needed
branch. Put an availability check before a condition that needs the value.

Expressions are limited to 64 KiB, 512 tokens, and 64 nested parser levels.
They cannot execute commands, read arbitrary files, or query other entries.
For collection-wide selection or external data, generate a
[mapping](mappings.md) with a program.
