//! Disposable transport comparison. Reads pre-signed URLs; no production defaults change.
use anyhow::{ensure, Result};
use aws_smithy_runtime_api::client::http::HttpConnector;
use aws_smithy_types::{body::SdkBody, byte_stream::ByteStream};
use futures_util::{stream, StreamExt, TryStreamExt};
use std::{
    fs::File,
    io::{Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
// Reuse syq's buffered destination writer, with diagnostics disabled.
#[allow(dead_code)]
#[path = "../src/s3/writer.rs"]
mod writer;
mod diagnostics {
    pub fn start() -> Option<std::time::Instant> {
        None
    }
    pub fn elapsed(_: Option<std::time::Instant>, _: &str, _: u64) {}
}

#[derive(Clone, serde::Deserialize)]
struct Object {
    url: String,
    size: usize,
    blake3: String,
}
const CHUNK: usize = 128 * 1024;
// Only sequential implementations use this setting; queued production batching
// stays unchanged as a reference.
fn sequential_chunk() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        let size = std::env::var("SYQ_SPIKE_CHUNK")
            .map(|s| s.parse::<usize>().expect("invalid chunk size"))
            .unwrap_or(CHUNK);
        assert!((4096..=8 * 1024 * 1024).contains(&size));
        size
    })
}
fn output(dir: &str, i: usize) -> Result<Option<File>> {
    Ok(if dir == "-" {
        None
    } else {
        Some(
            File::options()
                .write(true)
                .create_new(true)
                .open(format!("{dir}/{i}"))?,
        )
    })
}
fn finish(hasher: blake3::Hasher, object: &Object, bytes: usize) -> Result<()> {
    ensure!(bytes == object.size, "wrong body length");
    ensure!(
        hasher.finalize().to_hex().as_str() == object.blake3,
        "digest mismatch"
    );
    Ok(())
}
fn sync_get(agent: &ureq::Agent, object: &Object, dir: &str, i: usize) -> Result<()> {
    let request_probe = RequestProbe::start();
    let mut response = agent.get(&object.url).call()?;
    ensure!(response.status() == 200, "GET failed");
    let mut reader = response.body_mut().as_reader();
    let mut file = output(dir, i)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; sequential_chunk()];
    let mut bytes = 0;
    while bytes < object.size {
        let n = buffer.len().min(object.size - bytes);
        reader.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]);
        if let Some(f) = &mut file {
            f.write_all(&buffer[..n])?;
        }
        bytes += n;
    }
    ensure!(reader.read(&mut buffer[..1])? == 0, "extra body bytes");
    drop(request_probe);
    finish(hash, object, bytes)
}
// Optional diagnostic preload hook. No production code links to this symbol.
struct RequestProbe(Option<unsafe extern "C" fn(i32)>);
impl RequestProbe {
    fn start() -> Self {
        static HOOK: OnceLock<Option<unsafe extern "C" fn(i32)>> = OnceLock::new();
        let hook = *HOOK.get_or_init(|| {
            if std::env::var("SYQ_SPIKE_BUDGET_ACTIVE").as_deref() != Ok("1") {
                return None;
            }
            let symbol =
                unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"syq_spike_request_delta".as_ptr()) };
            assert!(!symbol.is_null(), "active-request probe hook missing");
            Some(unsafe {
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(i32)>(symbol)
            })
        });
        if let Some(hook) = hook {
            unsafe { hook(1) };
        }
        Self(hook)
    }
}
impl Drop for RequestProbe {
    fn drop(&mut self) {
        if let Some(hook) = self.0 {
            unsafe { hook(-1) };
        }
    }
}
// Exactly one explicit reusable data buffer per download, with no next read
// until its write completes. HTTP/TLS and kernel buffers are separate. The
// blocking worker owns file and buffer during the write, then returns them.
async fn async_sequential_get(
    connector: Arc<aws_smithy_http_client::Connector>,
    object: Object,
    dir: String,
    i: usize,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let request_probe = RequestProbe::start();
    let request = http::Request::builder()
        .uri(&object.url)
        .body(SdkBody::empty())?;
    let response = connector.call(request.try_into()?).await?;
    ensure!(response.status().as_u16() == 200, "GET failed");
    let mut reader = ByteStream::new(response.into_body()).into_async_read();
    let mut file = tokio::task::spawn_blocking(move || output(&dir, i)).await??;
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; sequential_chunk()];
    let mut bytes = 0;
    while bytes < object.size {
        let n = buffer.len().min(object.size - bytes);
        reader.read_exact(&mut buffer[..n]).await?;
        hash.update(&buffer[..n]);
        if let Some(mut destination) = file.take() {
            (destination, buffer) = tokio::task::spawn_blocking(move || {
                destination.write_all(&buffer[..n])?;
                Ok::<_, std::io::Error>((destination, buffer))
            })
            .await??;
            file = Some(destination);
        }
        bytes += n;
    }
    ensure!(
        reader.read(&mut buffer[..1]).await? == 0,
        "extra body bytes"
    );
    drop(request_probe);
    finish(hash, &object, bytes)
}
async fn async_get(
    connector: Arc<aws_smithy_http_client::Connector>,
    object: Object,
    dir: String,
    i: usize,
    destination: Option<(writer::Writer, u64)>,
) -> Result<()> {
    let request_probe = RequestProbe::start();
    let request = http::Request::builder()
        .uri(&object.url)
        .body(SdkBody::empty())?;
    let response = connector.call(request.try_into()?).await?;
    ensure!(response.status().as_u16() == 200, "GET failed");
    let mut body = ByteStream::new(response.into_body());
    let (writer, base_offset) = if let Some((writer, offset)) = destination {
        (Some(writer), offset)
    } else {
        let file = if dir == "-" {
            None
        } else {
            tokio::task::spawn_blocking(move || output(&dir, i)).await??
        };
        let writer = file
            .map(|f| writer::Writer::with_readback(Arc::new(f), object.size as u64, true))
            .transpose()?;
        (writer, 0)
    };
    let mut hash = blake3::Hasher::new();
    let mut bytes = 0;
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    let mut fragments = bytes::BytesMut::new();
    while let Some(frame) = body.next().await {
        let mut frame = frame?;
        hash.update(&frame);
        if let Some(w) = &writer {
            // Match download_fast_range's 128 KiB cap and fragment packing.
            while !frame.is_empty() {
                if batch_bytes == 0 && frame.len() >= CHUNK {
                    w.write(frame.split_to(CHUNK), base_offset + bytes as u64)
                        .await?;
                    bytes += CHUNK;
                    continue;
                }
                let n = frame.len().min(CHUNK - batch_bytes);
                let chunk = frame.split_to(n);
                if n < 4096 {
                    fragments.extend_from_slice(&chunk);
                } else {
                    flush_fragments(&mut batch, &mut fragments);
                    batch.push(chunk);
                }
                batch_bytes += n;
                bytes += n;
                if batch_bytes == CHUNK || batch.len() + usize::from(!fragments.is_empty()) >= 16 {
                    flush_fragments(&mut batch, &mut fragments);
                    w.write_batch(
                        std::mem::take(&mut batch),
                        base_offset + (bytes - batch_bytes) as u64,
                    )
                    .await?;
                    batch_bytes = 0;
                }
            }
        } else {
            bytes += frame.len();
        }
    }
    drop(request_probe);
    if let Some(w) = &writer {
        flush_fragments(&mut batch, &mut fragments);
        if !batch.is_empty() {
            w.write_batch(batch, base_offset + (bytes - batch_bytes) as u64)
                .await?;
        }
        w.finish().await?;
    }
    finish(hash, &object, bytes)
}
// Model several range readers sharing one destination queue. Each reader fetches
// a complete fixture object into a disjoint extent; this isolates writer contention.
async fn async_group(
    connector: Arc<aws_smithy_http_client::Connector>,
    object: Object,
    dir: String,
    i: usize,
    readers: usize,
) -> Result<()> {
    if readers == 1 {
        return async_get(connector, object, dir, i, None).await;
    }
    let file = tokio::task::spawn_blocking(move || output(&dir, i)).await??;
    let writer = writer::Writer::with_readback(
        Arc::new(file.expect("shared-writer probe requires files")),
        (object.size * readers) as u64,
        true,
    )?;
    let requests = (0..readers).map(|part| {
        let c = connector.clone();
        let o = object.clone();
        let w = writer.clone();
        async move {
            let offset = (part * o.size) as u64;
            tokio::spawn(async move { async_get(c, o, String::new(), 0, Some((w, offset))).await })
                .await?
        }
    });
    futures_util::future::try_join_all(requests).await?;
    writer.finish().await
}
fn flush_fragments(batch: &mut Vec<bytes::Bytes>, fragments: &mut bytes::BytesMut) {
    if !fragments.is_empty() {
        batch.push(std::mem::take(fragments).freeze());
    }
}
fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 3 && a[1] == "digest" {
        println!("{}", blake3::hash(&std::fs::read(&a[2])?).to_hex());
        return Ok(());
    }
    ensure!(
        a.len() == 7 || a.len() == 8,
        "MODE MANIFEST CONCURRENCY OUTPUT_DIR_OR_DASH CERT WORKER_THREADS [REPEATS]"
    );
    let objects: Vec<Object> = serde_json::from_slice(&std::fs::read(&a[2])?)?;
    ensure!(!objects.is_empty(), "empty manifest");
    let repeats: usize = a.get(7).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let jobs = objects
        .len()
        .checked_mul(repeats)
        .expect("job count overflow");
    let readers: usize = std::env::var("SYQ_SPIKE_READERS_PER_WRITER")
        .ok()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(1);
    ensure!(
        readers > 0 && jobs.is_multiple_of(readers),
        "incomplete reader group"
    );
    ensure!(
        a[1] == "async" || readers == 1,
        "shared writers require async"
    );
    let groups = jobs / readers;
    let serial_tail: usize = std::env::var("SYQ_SPIKE_SERIAL_TAIL")
        .ok()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(0);
    ensure!(serial_tail < groups, "tail consumes every group");
    ensure!(
        serial_tail == 0 || a[1] == "async" || a[1] == "async-sequential",
        "tail probe requires async"
    );
    let mut phase_elapsed = Vec::new();
    let concurrency: usize = a[3].parse()?;
    ensure!(concurrency > 0, "zero concurrency");
    let pem = std::fs::read(&a[5])?;
    let workers: usize = if a[6] == "auto" {
        std::thread::available_parallelism()?.get().min(32)
    } else {
        a[6].parse()?
    };
    let total: usize = objects.iter().map(|o| o.size).sum::<usize>() * repeats;
    let io_before = std::fs::read_to_string("/sys/fs/cgroup/io.stat").unwrap_or_default();
    let start = Instant::now();
    if a[1] == "sync" {
        let cert = ureq::tls::Certificate::from_pem(&pem)?;
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .max_idle_connections(concurrency)
            .max_idle_connections_per_host(concurrency)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(vec![cert].into())
                    .build(),
            )
            .build();
        let agent: ureq::Agent = config.into();
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| -> Result<()> {
            let handles: Vec<_> = (0..concurrency)
                .map(|_| {
                    s.spawn(|| -> Result<()> {
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= jobs {
                                break;
                            }
                            sync_get(&agent, &objects[i % objects.len()], &a[4], i)?;
                        }
                        Ok(())
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("worker panic")?;
            }
            Ok(())
        })?;
    } else {
        ensure!(
            a[1] == "async" || a[1] == "async-sequential",
            "unknown mode"
        );
        let sequential = a[1] == "async-sequential";
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()?;
        rt.block_on(async {
            let tls = aws_smithy_http_client::tls::TlsContext::builder()
                .with_trust_store(
                    aws_smithy_http_client::tls::TrustStore::empty().with_pem_certificate(pem),
                )
                .build()?;
            let connector = Arc::new(
                aws_smithy_http_client::Connector::builder()
                    .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                        aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
                    ))
                    .tls_context(tls)
                    .pool_max_idle_per_host(concurrency * readers)
                    .build(),
            );
            let phases = if serial_tail == 0 {
                vec![(0..groups, concurrency)]
            } else {
                vec![
                    (0..groups - serial_tail, concurrency),
                    (groups - serial_tail..groups, 1),
                ]
            };
            for (indices, limit) in phases {
                let phase_start = Instant::now();
                stream::iter(indices)
                    .map(|i| {
                        let o = objects[(i * readers) % objects.len()].clone();
                        let c = connector.clone();
                        let dir = a[4].clone();
                        async move {
                            tokio::spawn(async move {
                                tokio::time::timeout(Duration::from_secs(60), async move {
                                    if sequential {
                                        async_sequential_get(c, o, dir, i).await
                                    } else {
                                        async_group(c, o, dir, i, readers).await
                                    }
                                })
                                .await?
                            })
                            .await?
                        }
                    })
                    .buffer_unordered(limit)
                    .try_collect::<Vec<_>>()
                    .await?;
                phase_elapsed.push(phase_start.elapsed().as_secs_f64());
            }
            Ok::<_, anyhow::Error>(())
        })?;
    }
    let usage = unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut u);
        u
    };
    let cpu = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    println!(
        "{}",
        serde_json::json!({"mode":a[1],"chunk_bytes":if a[1] == "async" {CHUNK} else {sequential_chunk()},"objects":groups,"requests":jobs,"readers_per_writer":readers,"serial_tail":serial_tail,"phase_elapsed":phase_elapsed,"bytes":total,"concurrency":concurrency,"workers":workers,"elapsed":start.elapsed().as_secs_f64(),"user":cpu(usage.ru_utime),"system":cpu(usage.ru_stime),"rss_kib":usage.ru_maxrss,"voluntary":usage.ru_nvcsw,"involuntary":usage.ru_nivcsw,"io_before":io_before,"io_after":std::fs::read_to_string("/sys/fs/cgroup/io.stat").unwrap_or_default(),"memory_stat":std::fs::read_to_string("/sys/fs/cgroup/memory.stat").unwrap_or_default(),"memory_events":std::fs::read_to_string("/sys/fs/cgroup/memory.events").unwrap_or_default()})
    );
    Ok(())
}
