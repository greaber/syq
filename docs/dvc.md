# Pull and push DVC data

[`dvc_syq.py`](https://github.com/greaber/syq/blob/master/examples/dvc_syq.py)
does the work of `dvc pull` and `dvc push` with syq, and can be much faster.
DVC transfers objects one at a time from Python. The script works out every
copy in advance and gives syq the whole list in a single run. Repositories
with many files gain the most.

It is a short program written with the [Python SDK](python.md), meant to be
used, read, and adapted. DVC keeps working alongside it: both use the same
cache and the same remote, so `dvc status`, `dvc push`, and `dvc pull` treat
the script's results as their own.

## Run it

You need [uv](https://docs.astral.sh/uv/), which installs the script's
dependencies for you. Inside a DVC repository:

```sh
uv run https://raw.githubusercontent.com/greaber/syq/master/examples/dvc_syq.py pull
```

| Argument | Meaning |
|---|---|
| `pull` | Download missing objects into DVC's cache, then write the tracked files into the workspace |
| `fetch` | Download into the cache only |
| `push` | Upload cache objects that the remote does not have |
| `TARGET...` | After the command: `.dvc` files or tracked paths to limit it to. The default is everything tracked in the repository |
| `--remote NAME` | Use this DVC remote instead of the default one |
| `--dry-run` | Show what would be copied |
| `--force` | Let `pull` replace workspace files that have local changes |

## How it works

DVC names every stored file after its MD5 and lays out its cache exactly like
its remote. An object therefore has the same relative path in both places,
and only the last step, writing the workspace, gives files their real names.

```python
def object_path(md5):
    return f"files/md5/{md5[:2]}/{md5[2:]}"

# Remote to cache: the same path on both sides, plus the MD5 each file must have.
downloads = [
    MappingEntry(src=object_path(md5), dst=object_path(md5), expected_digest=Digest("md5", md5))
    for md5 in missing_from_cache
]
client.cp(mapping=downloads, from_="s3://my-bucket", into=".dvc/cache", only_new=True)

# Cache to workspace: each object gets the name recorded in the .dvc file.
checkout = [MappingEntry(src=object_path(md5), dst=path) for path, md5 in tracked_files]
client.cp(mapping=checkout, cwd=".dvc/cache", into=".")
```

Each list is a [mapping](mappings.md): pairs of source and destination paths
that syq copies in one run. Syq checks every download against its expected
MD5 before putting it in place. A file that does not match fails on its own
while the rest continue, and running the command again fetches only what is
still missing. A push is the first copy in reverse, and `only_new` makes it
skip objects the remote already has.

## Differences from DVC

- **Remotes.** Local directories, `ssh://host/path` without an explicit port,
  and `s3://bucket/prefix` are supported. For S3, the script reads
  `endpointurl`, `profile`, and `region` from the DVC remote and otherwise
  uses your usual AWS credentials. Other remote types, and remotes using
  DVC's cloud versioning, are refused.
- **Imported data.** `dvc pull` fetches `dvc import` data from the repository
  it came from. The script skips those files and says so; use `dvc pull` for
  them.
- **Untracked files in a tracked directory.** DVC refuses to pull until they
  are removed, and removes them with `--force`. The script leaves them alone.
- **Verification.** DVC does not check downloaded contents by default. The
  script checks the MD5 of every directory listing and of every file tracked
  by DVC 3. Files tracked by DVC 2 are not checked, because DVC 2 computed
  the MD5 of text files after changing their line endings.
- **Options.** `dvc pull` and `dvc push` options not in the table above, such
  as `--all-branches`, are not available.
