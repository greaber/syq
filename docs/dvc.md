# Pull and push DVC data

[`dvc_syq.py`](https://github.com/greaber/syq/blob/master/examples/dvc-syq/dvc_syq.py)
does the work of `dvc pull` and `dvc push` with syq, and can be faster. DVC
coordinates its transfers from a single Python process, which keeps it to
about one CPU core however many jobs it runs. The script works out every copy
in advance and hands the whole list to syq, which spreads the work over
several cores.

It is a short program written with the [Python SDK](python.md), meant to be
used, read, and adapted. DVC keeps working alongside it: both use the same
cache and the same remote, so `dvc status`, `dvc push`, and `dvc pull` treat
the script's results as their own.

## Run it

Install it as a `dvc-syq` command with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install 'git+https://github.com/greaber/syq#subdirectory=examples/dvc-syq'
```

Then, inside a DVC repository:

```sh
# Pull one tracked path, or the .dvc file that describes it.
dvc-syq pull models/speech.dvc

# Pull everything tracked under a directory; "-R ." covers the repository.
dvc-syq pull -R datasets

# Download into DVC's cache without touching the workspace.
dvc-syq fetch -R datasets

# Upload what the remote does not have yet.
dvc-syq push models/speech.dvc
```

`uv tool upgrade dvc-syq` fetches the current version. The script is also a
single file that declares its own dependencies, so you can download it and
run it without installing anything: `uv run dvc_syq.py pull -R datasets`.

These options have the same meaning as in DVC:

| Option | Meaning |
|---|---|
| `-R`, `--recursive` | Include every `.dvc` file under a directory target |
| `-r NAME`, `--remote NAME` | Use this DVC remote instead of the default one |
| `-f`, `--force` | Let `pull` replace files you have changed and remove untracked files from tracked directories. Without it, `pull` stops and lists them |

And two are the script's own:

| Option | Meaning |
|---|---|
| `--verify` | Check every download against its MD5. A file that does not match is kept out of the cache |
| `--dry-run` | Show what would be copied |

## How it works

DVC names every stored file after its MD5 and lays out its cache exactly like
its remote. An object therefore has the same relative path in both places,
and only the last step, writing the workspace, gives files their real names.

```python
def object_path(md5):
    return f"files/md5/{md5[:2]}/{md5[2:]}"

# Remote to cache: the same path on both sides.
downloads = [MappingEntry(src=object_path(md5), dst=object_path(md5)) for md5 in missing_from_cache]
client.cp(mapping=downloads, from_="s3://my-bucket", into=".dvc/cache", only_new=True)

# Cache to workspace: each object gets the name recorded in its .dvc file.
checkout = [MappingEntry(src=object_path(md5), dst=path) for path, md5 in tracked_files]
client.cp(mapping=checkout, cwd=".dvc/cache", into=".")
```

Each list is a [mapping](mappings.md): pairs of source and destination paths
that syq copies in one run. A push is the first copy in reverse, and
`only_new` makes it skip objects the remote already has. With `--verify`,
each download entry also carries the MD5 the file must have, and syq checks
it as the bytes arrive.

## Differences from DVC

- A target is required. DVC pulls or pushes the whole repository when you
  name none; here that is `-R .`.
- Remotes can be local directories, `ssh://host/path` without an explicit
  port, or `s3://bucket/prefix`. For S3 the script reads `endpointurl`,
  `profile`, and `region` from the DVC remote and otherwise uses your usual
  AWS credentials. Remotes that use DVC's cloud versioning are refused.
- Data brought in with `dvc import` is skipped with a message, because it
  lives in another repository's remote. Use `dvc pull` for it.
- DVC options not listed above, such as `--all-branches`, are not available.
