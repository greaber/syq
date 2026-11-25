//! Admit a batch's objects as fast as the request limit can use them.
//!
//! Objects do not have a controller of their own: the request limit in
//! `tuning` is the one measured quantity, and the number of objects in
//! progress follows it. An object takes a permit for each request it sends,
//! whether the request checks the object or transfers it, so objects that
//! turn out to need nothing hold no permit and finish at once.
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::watch;

/// Objects in progress for each request the limit allows. The objects
/// beyond the limit get ready meanwhile (read, hash or check local files)
/// and then wait for a permit, so requests never wait for preparation, and
/// that waiting shows the request limit there is demand for more.
const OBJECTS_PER_REQUEST: usize = 2;

pub(super) struct Concurrency {
    /// The most objects in progress: what the batch's memory and
    /// descriptors allow, or a count the user fixed.
    pub objects: usize,
    /// The most objects in progress that may be getting ready beside those
    /// the request limit already allows, such as files to upload that the
    /// upload buffers can hold while they wait: one prepared without room
    /// is read twice.
    pub ready: usize,
    /// The request limit the objects in progress follow. `None` keeps
    /// `objects` in progress.
    pub requests: Option<Arc<super::tuning::Budget>>,
}

impl Concurrency {
    /// The number of objects to keep in progress now.
    pub fn limit(&self) -> usize {
        match &self.requests {
            Some(requests) => {
                let limit = requests.limit();
                limit
                    .saturating_mul(OBJECTS_PER_REQUEST)
                    .min(self.ready)
                    .max(limit)
                    .min(self.objects)
            }
            None => self.objects,
        }
        .max(1)
    }
}

// Each object gets a runtime task so hashing and filesystem work can use more
// than one executor thread. JoinSet bounds live tasks and aborts them together
// when the copy is cancelled; detached uploads must never outlive the command.
pub(super) async fn parallel<T, F, Fut>(
    jobs: Vec<T>,
    concurrency: Concurrency,
    mut work: F,
) -> Result<()>
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut limits = concurrency
        .requests
        .as_ref()
        .map(|requests| requests.subscribe());
    let mut tasks = tokio::task::JoinSet::new();
    let mut jobs = jobs.into_iter();
    let mut error = None;
    loop {
        // A lower limit lets the objects in progress finish; it only
        // delays the next ones.
        let limit = concurrency.limit();
        while error.is_none() && tasks.len() < limit {
            let Some(job) = jobs.next() else { break };
            // A job's future can be tens of kilobytes. Box it once here
            // rather than move it into the task and again into its allocation.
            tasks.spawn(Box::pin(work(job)));
        }
        if tasks.is_empty() {
            break;
        }
        tokio::select! {
            result = tasks.join_next() => {
                if let Err(e) = result.unwrap().map_err(anyhow::Error::from).and_then(|r| r) {
                    error.get_or_insert(e);
                }
            }
            () = changed(&mut limits), if error.is_none() && jobs.len() > 0 => {}
        }
    }
    error.map_or(Ok(()), Err)
}

/// Completes when the request limit changes.
async fn changed(limits: &mut Option<watch::Receiver<usize>>) {
    let followed = match limits {
        Some(limits) => limits.changed().await.is_ok(),
        None => false,
    };
    if !followed {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
