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
        Arc,
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
    let mut response = agent.get(&object.url).call()?;
    ensure!(response.status() == 200, "GET failed");
    let mut reader = response.body_mut().as_reader();
    let mut file = output(dir, i)?;
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; CHUNK];
    let mut bytes = 0;
    while bytes < object.size {
        let n = CHUNK.min(object.size - bytes);
        reader.read_exact(&mut buffer[..n])?;
        hash.update(&buffer[..n]);
        if let Some(f) = &mut file {
            f.write_all(&buffer[..n])?;
        }
        bytes += n;
    }
    ensure!(reader.read(&mut buffer[..1])? == 0, "extra body bytes");
    finish(hash, object, bytes)
}
async fn async_get(
    connector: Arc<aws_smithy_http_client::Connector>,
    object: Object,
    dir: String,
    i: usize,
) -> Result<()> {
    let request = http::Request::builder()
        .uri(&object.url)
        .body(SdkBody::empty())?;
    let response = connector.call(request.try_into()?).await?;
    ensure!(response.status().as_u16() == 200, "GET failed");
    let mut body = ByteStream::new(response.into_body());
    let file = if dir == "-" {
        None
    } else {
        tokio::task::spawn_blocking(move || output(&dir, i)).await??
    };
    let writer = file
        .map(|f| writer::Writer::with_readback(Arc::new(f), object.size as u64, true))
        .transpose()?;
    let mut hash = blake3::Hasher::new();
    let mut bytes = 0;
    let mut batch = Vec::new();
    let mut batch_bytes = 0;
    while let Some(frame) = body.next().await {
        let frame = frame?;
        hash.update(&frame);
        bytes += frame.len();
        if let Some(w) = &writer {
            batch_bytes += frame.len();
            batch.push(frame);
            if batch_bytes >= CHUNK {
                w.write_batch(std::mem::take(&mut batch), (bytes - batch_bytes) as u64)
                    .await?;
                batch_bytes = 0;
            }
        }
    }
    if let Some(w) = &writer {
        if !batch.is_empty() {
            w.write_batch(batch, (bytes - batch_bytes) as u64).await?;
        }
        w.finish().await?;
    }
    finish(hash, &object, bytes)
}
fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let a: Vec<String> = std::env::args().collect();
    if a.len() == 3 && a[1] == "digest" {
        println!("{}", blake3::hash(&std::fs::read(&a[2])?).to_hex());
        return Ok(());
    }
    ensure!(
        a.len() == 7,
        "MODE MANIFEST CONCURRENCY OUTPUT_DIR_OR_DASH CERT WORKER_THREADS"
    );
    let objects: Vec<Object> = serde_json::from_reader(File::open(&a[2])?)?;
    let concurrency: usize = a[3].parse()?;
    ensure!(concurrency > 0, "zero concurrency");
    let pem = std::fs::read(&a[5])?;
    let workers: usize = a[6].parse()?;
    let total: usize = objects.iter().map(|o| o.size).sum();
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
                            if i >= objects.len() {
                                break;
                            }
                            sync_get(&agent, &objects[i], &a[4], i)?;
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
        ensure!(a[1] == "async", "unknown mode");
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
                    .pool_max_idle_per_host(concurrency)
                    .build(),
            );
            stream::iter(objects.iter().cloned().enumerate())
                .map(|(i, o)| {
                    let c = connector.clone();
                    let dir = a[4].clone();
                    async move {
                        tokio::spawn(async move {
                            tokio::time::timeout(Duration::from_secs(60), async_get(c, o, dir, i))
                                .await?
                        })
                        .await?
                    }
                })
                .buffer_unordered(concurrency)
                .try_collect::<Vec<_>>()
                .await?;
            Ok::<_, anyhow::Error>(())
        })?;
    }
    println!(
        "{}",
        serde_json::json!({"mode":a[1],"objects":objects.len(),"bytes":total,"concurrency":concurrency,"workers":workers,"elapsed":start.elapsed().as_secs_f64()})
    );
    Ok(())
}
