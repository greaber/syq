//! RSB-compatible sharded archives, produced and consumed through one syq session.
mod session;
use anyhow::{bail, ensure, Context, Result};
use arrow_array::{
    Array, ArrayRef, Int64Array, LargeStringArray, RecordBatch, StringArray, StringViewArray,
};
use arrow_schema::{DataType, Field, Schema};
use clap::{Parser, Subcommand};
use parquet::{
    arrow::{arrow_reader::ParquetRecordBatchReaderBuilder, ArrowWriter},
    basic::Compression,
    file::properties::WriterProperties,
};
use session::{Client, Entry};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File},
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Parser)]
#[command(about = "Stream RSB-compatible tar shards through syq")]
struct Options {
    #[arg(long, default_value = "syq", global = true)]
    syq: OsString,
    #[arg(long, default_value_t = 8, global = true)]
    jobs: usize,
    /// Additional syq option, for example --syq-arg=--no-compress. Repeat as needed.
    #[arg(long, global = true)]
    syq_arg: Vec<OsString>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Pack and upload to a new prefix, then publish the manifest and optional RSB record.
    Push {
        source: PathBuf,
        prefix: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = 536870912)]
        shard_bytes: u64,
        /// Existing .rsb record whose fields should be preserved.
        #[arg(long, requires = "remote_name")]
        record: Option<PathBuf>,
        /// Remote name appended to the record's pushes list.
        #[arg(long, requires = "record")]
        remote_name: Option<String>,
    },
    /// Download and extract into DESTINATION.unsharding, then rename on success.
    Pull {
        prefix: String,
        destination: PathBuf,
        #[arg(long)]
        from: Option<String>,
    },
}
#[derive(Debug, Clone)]
struct Row {
    shard: i64,
    index: i64,
    path: String,
    size: i64,
}
fn path_string(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("RSB manifests require UTF-8 paths")?
        .to_owned())
}
fn relative(path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty()
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "invalid manifest path: {}",
        path.display()
    );
    Ok(())
}
fn placement(
    flag: &str,
    prefix: &str,
    endpoint_flag: &str,
    endpoint: &Option<String>,
) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(endpoint) = endpoint {
        args.extend([endpoint_flag.into(), endpoint.into()]);
    }
    args.extend([flag.into(), prefix.into()]);
    args
}
fn upload(path: String, work: impl Fn(&mut File) -> Result<()> + Send + Sync + 'static) -> Entry {
    Entry {
        path,
        upload: true,
        work: Box::new(work),
    }
}
fn download(path: String, work: impl Fn(&mut File) -> Result<()> + Send + Sync + 'static) -> Entry {
    Entry {
        path,
        upload: false,
        work: Box::new(work),
    }
}

type Shards = (Vec<Vec<PathBuf>>, Vec<PathBuf>, Vec<Row>);
fn scan(source: &Path, shard_bytes: u64) -> Result<Shards> {
    ensure!(source.is_dir(), "source is not a directory");
    ensure!(shard_bytes > 0, "shard-bytes must be positive");
    let mut shards = Vec::new();
    let mut empty = Vec::new();
    let mut rows = Vec::new();
    let mut shard = Vec::new();
    let mut size = 0u64;
    for item in walkdir::WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
    {
        let item = item?;
        let name = item.path().strip_prefix(source)?;
        if item.file_type().is_dir() {
            if fs::read_dir(item.path())?.next().transpose()?.is_none() {
                empty.push(if name.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    name.to_owned()
                });
            }
            continue;
        }
        ensure!(
            item.file_type().is_file() || item.file_type().is_symlink(),
            "unsupported source kind: {}",
            item.path().display()
        );
        let length = fs::metadata(item.path())
            .ok()
            .filter(|m| m.is_file() && !item.file_type().is_symlink())
            .map_or(0, |m| m.len());
        rows.push(Row {
            shard: shards.len().try_into()?,
            index: rows.len().try_into()?,
            path: path_string(name)?,
            size: length.try_into()?,
        });
        size = size.checked_add(length).context("shard size overflow")?;
        shard.push(name.to_owned());
        if size >= shard_bytes || shard.len() >= 10_000 {
            shards.push(std::mem::take(&mut shard));
            size = 0;
        }
    }
    if !shard.is_empty() {
        shards.push(shard);
    }
    for name in &empty {
        rows.push(Row {
            shard: shards.len().try_into()?,
            index: rows.len().try_into()?,
            path: path_string(name)?,
            size: 0,
        });
    }
    Ok((shards, empty, rows))
}
fn archive(source: &Path, names: &[PathBuf], output: &mut File) -> Result<()> {
    let mut tar = tar::Builder::new(output);
    tar.follow_symlinks(false);
    for name in names {
        let path = source.join(name);
        let meta = fs::symlink_metadata(&path)?;
        let nanos = i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec());
        let stamp = format!(
            "{}{}.{:09}",
            if nanos < 0 { "-" } else { "" },
            nanos.abs() / 1_000_000_000,
            nanos.abs() % 1_000_000_000
        );
        tar.append_pax_extensions([("mtime", stamp.as_bytes())])?;
        tar.append_path_with_name(path, name)?;
    }
    tar.finish()?;
    Ok(())
}
fn empty_archive(names: &[PathBuf], output: &mut File) -> Result<()> {
    let mut tar = tar::Builder::new(output);
    for name in names {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, name, std::io::empty())?;
    }
    tar.finish()?;
    Ok(())
}
fn write_manifest(rows: &[Row], output: &mut File) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("shard_idx", DataType::Int64, false),
        Field::new("idx", DataType::Int64, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("size", DataType::Int64, false),
    ]));
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.shard))),
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.index))),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.path.as_str()),
        )),
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.size))),
    ];
    let batch = RecordBatch::try_new(schema.clone(), columns)?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut writer = ArrowWriter::try_new(output, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}
fn read_manifest(input: File) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for batch in ParquetRecordBatchReaderBuilder::try_new(input)?.build()? {
        let batch = batch?;
        let column = |name| {
            batch
                .column_by_name(name)
                .with_context(|| format!("manifest is missing {name}"))
        };
        let ints = |name| {
            column(name)?
                .as_any()
                .downcast_ref::<Int64Array>()
                .with_context(|| format!("{name} must contain signed 64-bit integers"))
        };
        let shards = ints("shard_idx")?;
        let indices = ints("idx")?;
        let sizes = ints("size")?;
        let paths = column("path")?;
        for i in 0..batch.num_rows() {
            ensure!(
                !shards.is_null(i) && !indices.is_null(i) && !sizes.is_null(i) && !paths.is_null(i),
                "manifest contains null values"
            );
            let path = if let Some(a) = paths.as_any().downcast_ref::<StringArray>() {
                a.value(i)
            } else if let Some(a) = paths.as_any().downcast_ref::<LargeStringArray>() {
                a.value(i)
            } else if let Some(a) = paths.as_any().downcast_ref::<StringViewArray>() {
                a.value(i)
            } else {
                bail!("manifest path must contain strings");
            };
            ensure!(
                shards.value(i) >= 0 && sizes.value(i) >= 0,
                "negative manifest shard or size"
            );
            rows.push(Row {
                shard: shards.value(i),
                index: indices.value(i),
                path: path.to_owned(),
                size: sizes.value(i),
            });
        }
    }
    Ok(rows)
}
fn pax_mtime(text: &str) -> Result<filetime::FileTime> {
    // Python writes decimal seconds, sometimes with an exponent. Decode without
    // a float round-trip, which loses nanoseconds on modern timestamps.
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let exponent: i32 = exponent.parse()?;
    let negative = mantissa.starts_with('-');
    let unsigned = mantissa.trim_start_matches(['-', '+']);
    let (seconds, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    ensure!(
        !seconds.is_empty()
            && seconds
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit()),
        "invalid PAX mtime"
    );
    let digits: i128 = format!("{seconds}{fraction}").parse()?;
    let scale = 9i32
        .checked_add(exponent)
        .and_then(|n| n.checked_sub(fraction.len().try_into().ok()?))
        .context("PAX mtime out of range")?;
    let factor = 10i128
        .checked_pow(scale.unsigned_abs())
        .context("PAX mtime out of range")?;
    let nanos = if scale >= 0 {
        digits
            .checked_mul(factor)
            .context("PAX mtime out of range")?
    } else {
        digits / factor
    } * if negative { -1 } else { 1 };
    Ok(filetime::FileTime::from_unix_time(
        nanos.div_euclid(1_000_000_000).try_into()?,
        nanos.rem_euclid(1_000_000_000) as u32,
    ))
}
fn entry_mtime(entry: &mut tar::Entry<'_, &mut File>) -> Result<filetime::FileTime> {
    let mut time = filetime::FileTime::from_unix_time(entry.header().mtime()? as i64, 0);
    if let Some(extensions) = entry.pax_extensions()? {
        for field in extensions {
            let field = field?;
            if field.key_bytes() != b"mtime" {
                continue;
            }
            let text = std::str::from_utf8(field.value_bytes())?;
            time = pax_mtime(text)?;
        }
    }
    Ok(time)
}
fn extract(destination: &Path, input: &mut File) -> Result<()> {
    let mut archive = tar::Archive::new(input);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(unsafe { libc::geteuid() } == 0);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        let mtime = entry_mtime(&mut entry)?;
        ensure!(
            entry.unpack_in(destination)?,
            "invalid archive path: {}",
            name.display()
        );
        // tar-rs currently applies whole-second header times, not PAX fractions.
        filetime::set_symlink_file_times(destination.join(name), mtime, mtime)?;
    }
    Ok(())
}
fn push(
    client: &Client,
    source: PathBuf,
    prefix: String,
    to: Option<String>,
    shard_bytes: u64,
    record: Option<PathBuf>,
    remote_name: Option<String>,
) -> Result<()> {
    let source = fs::canonicalize(source)?;
    // Validate the optional record before creating any remote objects.
    let record = record
        .map(|path| -> Result<Vec<u8>> {
            let mut record: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
            ensure!(
                record["sharded_by_rsb"] == true,
                "record does not describe an RSB-sharded dataset"
            );
            let pushes = record["pushes"]
                .as_array_mut()
                .context("record pushes is not a list")?;
            pushes.push(remote_name.context("missing remote name")?.into());
            record["stage"] = "ap".into();
            Ok(serde_json::to_vec(&record)?)
        })
        .transpose()?;
    let (shards, empty, rows) = scan(&source, shard_bytes)?;
    let mut entries = Vec::new();
    for (i, names) in shards.into_iter().enumerate() {
        let source = source.clone();
        entries.push(upload(format!("shard_{i}.tar"), move |out| {
            archive(&source, &names, out)
        }));
    }
    entries.push(upload("empty_dirs.tar".into(), move |out| {
        empty_archive(&empty, out)
    }));
    let stats = client.run(&entries, &placement("--into-new", &prefix, "--to", &to))?;
    ensure!(stats.skipped == 0, "a shard was skipped");
    let manifest = upload("manifest.parquet".into(), move |out| {
        write_manifest(&rows, out)
    });
    let manifest_stats = client.run(&[manifest], &placement("--into", &prefix, "--to", &to))?;
    ensure!(manifest_stats.skipped == 0, "manifest was skipped");
    if let Some(record) = record {
        let record_path = PathBuf::from(format!("{}.rsb", prefix.trim_end_matches('/')));
        let parent = record_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path_string(Path::new(
            record_path.file_name().context("invalid prefix")?,
        ))?;
        let entry = upload(name, move |out| {
            out.write_all(&record)?;
            Ok(())
        });
        let mut args = vec![OsString::from("--only-new")];
        args.extend(placement("--into", &path_string(parent)?, "--to", &to));
        ensure!(
            client.run(&[entry], &args)?.skipped == 0,
            "record already exists; uploaded shards were left at the new prefix"
        );
    }
    eprintln!(
        "Uploaded {} archive streams ({} bytes)",
        entries.len(),
        stats.bytes
    );
    Ok(())
}
fn pull(client: &Client, prefix: String, destination: PathBuf, from: Option<String>) -> Result<()> {
    ensure!(!destination.try_exists()?, "destination already exists");
    let mut stage_name = destination.as_os_str().to_owned();
    stage_name.push(".unsharding");
    let staging = PathBuf::from(stage_name);
    fs::create_dir(&staging)
        .context("create staging directory; remove an interrupted staging tree before retrying")?;
    let manifest = tempfile::tempfile()?;
    let manifest_writer = Arc::new(Mutex::new(manifest.try_clone()?));
    let empty_names = Arc::new(Mutex::new(BTreeSet::new()));
    let names = empty_names.clone();
    let stage = staging.clone();
    let entries = [
        download("manifest.parquet".into(), move |inp| {
            std::io::copy(inp, &mut *manifest_writer.lock().unwrap())?;
            Ok(())
        }),
        download("empty_dirs.tar".into(), move |inp| {
            let mut archive = tar::Archive::new(inp);
            for entry in archive.entries()? {
                let mut entry = entry?;
                ensure!(
                    entry.header().entry_type().is_dir(),
                    "empty_dirs.tar contains a non-directory"
                );
                names.lock().unwrap().insert(path_string(&entry.path()?)?);
                ensure!(entry.unpack_in(&stage)?, "invalid empty directory path");
            }
            Ok(())
        }),
    ];
    let mut args: Vec<OsString> = vec!["--cwd".into(), prefix.into()];
    if let Some(from) = from {
        args.extend(["--from".into(), from.into()]);
    }
    args.extend(["--into".into(), ".".into()]);
    let stats = client.run(&entries, &args)?;
    ensure!(stats.skipped == 0, "index download was skipped");
    let rows = read_manifest(manifest)?;
    let empty = empty_names.lock().unwrap();
    let mut ids = BTreeSet::new();
    // RSB assigns empty directories the next unused shard ID. Their manifest
    // paths need not match tar names (older records can contain absolute paths).
    let empty_shard = (!empty.is_empty())
        .then(|| rows.iter().map(|r| r.shard).max())
        .flatten();
    for row in rows {
        if Some(row.shard) == empty_shard {
            continue;
        }
        let path = Path::new(&row.path);
        relative(path)?;
        fs::create_dir_all(staging.join(path).parent().unwrap())?;
        ids.insert(row.shard);
    }
    let entries: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let staging = staging.clone();
            download(format!("shard_{id}.tar"), move |input| {
                extract(&staging, input)
            })
        })
        .collect();
    let stats = client.run(&entries, &args)?;
    ensure!(stats.skipped == 0, "an archive was skipped");
    ensure!(
        !destination.try_exists()?,
        "destination appeared during extraction"
    );
    fs::rename(&staging, &destination)?;
    eprintln!("Restored {} shards ({} bytes)", entries.len(), stats.bytes);
    Ok(())
}
fn main() -> Result<()> {
    let options = Options::parse();
    let client = Client {
        executable: options.syq,
        options: options.syq_arg,
        jobs: options.jobs,
    };
    match options.command {
        Action::Push {
            source,
            prefix,
            to,
            shard_bytes,
            record,
            remote_name,
        } => push(
            &client,
            source,
            prefix,
            to,
            shard_bytes,
            record,
            remote_name,
        ),
        Action::Pull {
            prefix,
            destination,
            from,
        } => pull(&client, prefix, destination, from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn pax_times_keep_fractional_and_negative_seconds() {
        for (value, seconds, nanos) in [
            ("1700000000.123456789", 1700000000, 123456789),
            ("-0.25", -1, 750000000),
            ("1e-09", 0, 1),
            ("1.7e9", 1700000000, 0),
        ] {
            let time = pax_mtime(value).unwrap();
            assert_eq!((time.unix_seconds(), time.nanoseconds()), (seconds, nanos));
        }
    }

    #[test]
    #[ignore = "requires SYQ_CANDIDATE_EXECUTABLE; run explicitly with --include-ignored"]
    fn archive_roundtrip_and_failure_leave_destination_safe() -> Result<()> {
        let client = Client {
            executable: std::env::var_os("SYQ_CANDIDATE_EXECUTABLE")
                .context("set SYQ_CANDIDATE_EXECUTABLE")?,
            options: vec!["--no-progress".into()],
            jobs: 2,
        };
        let temp = tempfile::tempdir()?;
        let src = temp.path().join("source");
        fs::create_dir_all(src.join("nested/empty"))?;
        for i in 0..6 {
            let path = src.join(format!("nested/{i}"));
            fs::write(&path, vec![i; 10000])?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
            let time = pax_mtime("1700000000.123456789")?;
            filetime::set_file_times(path, time, time)?;
        }
        symlink("nested/0", src.join("link"))?;
        symlink("absent", src.join("dangling"))?;
        let prefix = temp.path().join("packed");
        push(
            &client,
            src.clone(),
            path_string(&prefix)?,
            None,
            16000,
            None,
            None,
        )?;
        let dst = temp.path().join("restored");
        pull(&client, path_string(&prefix)?, dst.clone(), None)?;
        for i in 0..6 {
            let name = format!("nested/{i}");
            assert_eq!(fs::read(src.join(&name))?, fs::read(dst.join(&name))?);
            let meta = fs::metadata(dst.join(&name))?;
            assert_eq!(
                (meta.mode() & 0o777, meta.mtime(), meta.mtime_nsec()),
                (0o640, 1700000000, 123456789)
            );
        }
        assert_eq!(
            fs::read_link(dst.join("dangling"))?,
            PathBuf::from("absent")
        );
        assert!(dst.join("nested/empty").is_dir());
        fs::write(prefix.join("shard_0.tar"), b"broken archive")?;
        let failed = temp.path().join("failed");
        assert!(pull(&client, path_string(&prefix)?, failed.clone(), None).is_err());
        assert!(!failed.exists());
        let existing = temp.path().join("existing");
        fs::write(&existing, b"old")?;
        let bad = upload("existing".into(), |out| {
            out.write_all(b"partial")?;
            bail!("producer failed")
        });
        assert!(client
            .run(&[bad], &["--into".into(), temp.path().into()])
            .is_err());
        assert_eq!(fs::read(existing)?, b"old");
        Ok(())
    }
}
