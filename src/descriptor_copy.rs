//! Raw byte copies through caller-owned descriptors. The named counterpart is
//! one regular file or one exact S3 key; no file-tree or recovery state is made.
pub(crate) mod fd;
mod file;

use crate::{
    cli::{Args, Location},
    conn,
    proto::{Request, Response},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering::Relaxed},
    Arc,
};

const CHUNK: usize = 4 * 1024 * 1024;
const PIPELINE: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub source: Option<fd::Source>,
    pub as_fd: Option<i32>,
    pub location: Option<Location>,
    pub key: Option<String>,
    pub follow: bool,
}

// Append-only member of Request. Only unrestricted control sessions may use
// this protocol; it never interprets grants or existing recovery records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Operation {
    Open {
        path: Vec<u8>,
        write: bool,
        follow: bool,
    },
    Read,
    Write {
        off: u64,
        hash: [u8; 32],
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Finish {
        size: u64,
        hash: [u8; 32],
    },
}
pub(crate) use file::Session;

type Reply = tokio::sync::oneshot::Sender<Result<Vec<Response>>>;
struct Connection {
    requests: Option<std::sync::mpsc::Sender<(Vec<Operation>, Reply)>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Connection {
    fn start(args: Args, location: Location) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<(Vec<Operation>, Reply)>();
        let worker = std::thread::spawn(move || {
            let connection = crate::transfer::endpoint(&location, &args)
                .and_then(|endpoint| endpoint.connect_control(args.compress));
            match connection {
                Ok(mut connection) => {
                    while let Ok((operations, reply)) = rx.recv() {
                        let response = (|| {
                            let count = operations.len();
                            for operation in operations {
                                connection.send(Request::DescriptorCopy(operation))?;
                            }
                            // Drain every reply even on endpoint errors, so orderly
                            // shutdown never leaves a helper blocked on its output.
                            let mut responses = Vec::with_capacity(count);
                            let mut error = None;
                            for _ in 0..count {
                                match conn::ok(connection.recv()?, "descriptor copy") {
                                    Ok(response) => responses.push(response),
                                    Err(e) => {
                                        error.get_or_insert(e);
                                    }
                                }
                            }
                            error.map_or(Ok(responses), Err)
                        })();
                        let failed = response.is_err();
                        if reply.send(response).is_err() || failed {
                            break;
                        }
                    }
                }
                Err(error) => {
                    if let Ok((_, reply)) = rx.recv() {
                        let _ = reply.send(Err(error));
                    }
                }
            }
        });
        Self {
            requests: Some(tx),
            worker: Some(worker),
        }
    }
    async fn call(&self, operation: Operation) -> Result<Response> {
        Ok(self.batch(vec![operation]).await?.remove(0))
    }
    async fn batch(&self, operations: Vec<Operation>) -> Result<Vec<Response>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.requests
            .as_ref()
            .unwrap()
            .send((operations, tx))
            .map_err(|_| anyhow::anyhow!("descriptor connection closed"))?;
        rx.await.context("descriptor connection closed")?
    }
    async fn close(mut self) {
        self.requests.take();
        let worker = self.worker.take().unwrap();
        if tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(move || worker.join()),
        )
        .await
        .is_err()
        {
            crate::output::diagnostic!(
                "syq cp: could not confirm stream cleanup at the file endpoint"
            );
        }
    }
}

pub(crate) fn run(mut args: Args) -> Result<i32> {
    let plan = args.descriptor_copy.take().unwrap();
    if let Some(options) = args.s3.take() {
        return crate::s3::stream::run(options, plan.key.unwrap(), plan.source, plan.as_fd);
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut connection = None;
        let operation = async {
            // Protect inherited descriptors before starting any children. FIFO
            // opening is also inside cancellation, including waits for writers.
            let input = match plan.source.clone() {
                Some(source) => Some(source.open(cancelled.clone()).await?),
                None => None,
            };
            let output = plan.as_fd.map(|n| fd::Descriptor::open(n, false, cancelled.clone())).transpose()?;
            connection = plan.location.clone().map(|location| Connection::start(args, location));
            copy(&plan, input, output, connection.as_ref()).await
        };
        let result = tokio::select! {
            result = operation => result,
            result = tokio::signal::ctrl_c() => { result?; Err(anyhow::anyhow!("descriptor copy cancelled")) },
            _ = term.recv() => Err(anyhow::anyhow!("descriptor copy cancelled")),
        };
        cancelled.store(true, Relaxed);
        if let Some(connection) = connection { connection.close().await; }
        result
    });
    cancelled.store(true, Relaxed);
    // A blocking caller-owned pipe cannot be interrupted without changing its
    // shared flags. main exits after cleanup, terminating any blocked worker.
    runtime.shutdown_background();
    result.map(|()| 0)
}

async fn copy(
    plan: &Plan,
    mut input: Option<fd::Descriptor>,
    mut output: Option<fd::Descriptor>,
    connection: Option<&Connection>,
) -> Result<()> {
    if let Some(connection) = connection {
        match connection
            .call(Operation::Open {
                path: plan.location.as_ref().unwrap().path.clone(),
                write: input.is_some(),
                follow: plan.follow,
            })
            .await?
        {
            Response::Ok => {}
            _ => bail!("unexpected stream open response"),
        }
    }
    let mut off = 0u64;
    let mut hash = blake3::Hasher::new();
    loop {
        let blocks: Vec<bytes::Bytes> = if let Some(descriptor) = input.take() {
            let (descriptor, data) = descriptor.read_available(CHUNK * PIPELINE).await?;
            input = Some(descriptor);
            (0..data.len())
                .step_by(CHUNK)
                .map(|start| data.slice(start..(start + CHUNK).min(data.len())))
                .collect()
        } else {
            let replies = connection
                .unwrap()
                .batch(vec![Operation::Read; PIPELINE])
                .await?;
            let mut expected = off;
            let mut blocks = Vec::new();
            let mut ended = false;
            for reply in replies {
                match reply {
                    Response::Block {
                        off: received,
                        hash,
                        data,
                    } if received == expected
                        && data.len() <= CHUNK
                        && hash == *blake3::hash(&data).as_bytes() =>
                    {
                        anyhow::ensure!(!ended || data.is_empty(), "payload after stream EOF");
                        ended |= data.is_empty();
                        expected = expected
                            .checked_add(data.len() as u64)
                            .context("stream length overflow")?;
                        if !data.is_empty() {
                            blocks.push(data.into());
                        }
                    }
                    _ => bail!("invalid descriptor stream block"),
                }
            }
            blocks
        };
        if blocks.is_empty() {
            break;
        }
        let mut writes = Vec::new();
        for data in blocks {
            hash.update(&data);
            let length = data.len() as u64;
            if let Some(descriptor) = output.take() {
                output = Some(descriptor.write_chunk(data).await?);
            } else {
                writes.push(Operation::Write {
                    off,
                    hash: *blake3::hash(&data).as_bytes(),
                    data: data.to_vec(),
                });
            }
            off = off.checked_add(length).context("stream length overflow")?;
        }
        if !writes.is_empty() {
            for response in connection.unwrap().batch(writes).await? {
                anyhow::ensure!(
                    matches!(response, Response::Ok),
                    "unexpected stream write response"
                );
            }
        }
    }
    if let Some(connection) = connection {
        match connection
            .call(Operation::Finish {
                size: off,
                hash: *hash.finalize().as_bytes(),
            })
            .await?
        {
            Response::Ok => {}
            _ => bail!("unexpected stream completion response"),
        }
    }
    Ok(())
}
