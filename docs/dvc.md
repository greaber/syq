# Pull and push DVC data

[DVC](https://dvc.org) keeps large files out of Git. It stores each tracked
file in a remote, such as an S3 bucket, under a name made from the file's MD5,
and commits small `.dvc` files that record those hashes. A tracked directory
gets one extra object listing the files inside it.

Because every object's location follows from its hash, a script can work out
the complete list of copies before it starts and give syq that list at once.
[`dvc_syq.py`](https://github.com/greaber/syq/blob/master/examples/dvc_syq.py)
does this with the [Python SDK](python.md). It is an example to use, copy, and
adapt, written to show what [mappings](mappings.md) make possible.

## Run it

You need [uv](https://docs.astral.sh/uv/), which installs the script's
dependencies for you. Inside a DVC repository:

```sh
uv run https://raw.githubusercontent.com/greaber/syq/master/examples/dvc_syq.py pull
```

| Command | What it does |
|---|---|
| `pull` | Downloads missing objects into DVC's cache, then writes the tracked files into your workspace |
| `fetch` | Downloads into the cache only |
| `push` | Uploads cache objects that the remote does not have |

Name `.dvc` files or tracked paths after the command to limit it; otherwise
it covers every `.dvc` file and `dvc.lock` in the repository. `--remote NAME`
selects a remote other than the default, and `--dry-run` previews. A dry run
of `pull` stops early when directory listings still need downloading, because
the files inside those directories are unknown until then.

DVC keeps working alongside the script. Both use the same cache and the same
remote layout, so `dvc status`, `dvc push`, and `dvc pull` see the script's
results as their own.

## How it works

The heart of a pull is one mapping: each entry names an object in the remote,
where it belongs in the cache, and the MD5 it must have.

```python
entries = [
    MappingEntry(
        src=f"files/md5/{md5[:2]}/{md5[2:]}",
        dst=f"files/md5/{md5[:2]}/{md5[2:]}",
        kind="file",
        expected_digest=Digest("md5", md5),
    )
    for md5 in missing
]
client.cp(mapping=entries, from_="s3://my-bucket", into=".dvc/cache", only_new=True)
```

Syq checks each downloaded file against its
[expected digest](mappings.md#the-format) before putting it in place. A file
that does not match fails on its own while the rest continue, and running the
command again retries only what is missing. `only_new` makes a push skip
objects the remote already has. A second, local mapping copies from the cache
into the workspace, [cloning files](speed.md) where the filesystem allows.

## What it supports

- Remotes that are local directories, `ssh://host/path`, or
  `s3://bucket/prefix`. For S3 it reads `endpointurl`, `profile`, and `region`
  from the DVC remote and otherwise uses your
  [usual AWS credentials](object-storage.md#credentials-and-providers). SSH
  remotes with an explicit port are refused.
- Repositories written by DVC 2 and DVC 3. DVC 2 objects live at the top of
  the cache instead of under `files/md5`, and DVC 2 computed the MD5 of text
  files after normalizing line endings, so those objects are copied without a
  digest check.
- `pull` replaces workspace files that differ from the tracked version, as
  `dvc checkout --force` would.

The script does not hash new data or write `.dvc` files; keep using `dvc add`
for that. It also leaves remote cleanup to `dvc gc`.
