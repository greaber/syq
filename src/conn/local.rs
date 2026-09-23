use super::*;

pub struct LocalConn {
    pub(super) rpc_observation: Option<RpcObservation>,
    pub(super) ops: FsOps,
    pub(super) pending: VecDeque<Response>,
    pub(super) role: LocalConnectionRole,
    pub(super) read_stream: Option<ReadStreamRequest>,
    pub(super) read_stream_limit: u64,
    pub(super) read_stream_done_sent: bool,
    pub(super) write_stream: Option<crate::streaming::Completions>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalConnectionRole {
    Control,
    SourceWorker,
    DestinationWorker,
    StreamWorker,
}

impl From<&ConnectionRole> for LocalConnectionRole {
    fn from(role: &ConnectionRole) -> Self {
        match role {
            ConnectionRole::Control => Self::Control,
            ConnectionRole::SourceWorker { .. } => Self::SourceWorker,
            ConnectionRole::DestinationWorker { .. } => Self::DestinationWorker,
            ConnectionRole::StreamWorker { .. } => Self::StreamWorker,
        }
    }
}

impl LocalConn {
    pub(super) fn new(
        role: &ConnectionRole,
        descriptor_session: crate::descriptor_broker::DescriptorSessionSlot,
    ) -> Self {
        LocalConn {
            ops: FsOps::with_descriptor_session(descriptor_session),
            pending: VecDeque::new(),
            role: role.into(),
            read_stream: None,
            read_stream_limit: 0,
            read_stream_done_sent: false,
            rpc_observation: None,
            write_stream: None,
        }
    }
}

impl Conn for LocalConn {
    fn observe(
        &mut self,
        observations: &crate::transfer_observations::Observations,
        actor: &std::sync::Arc<crate::transfer_observations::Actor>,
        source: bool,
        worker_id: usize,
    ) -> Result<()> {
        if self.rpc_observation.is_none() {
            self.ops.observations.enable();
            observations.local(
                format!(
                    "{} worker {worker_id}",
                    if source { "source" } else { "destination" }
                ),
                self.ops.observations.clone(),
            );
        }
        self.rpc_observation = Some(RpcObservation {
            actor: actor.clone(),
            source,
        });
        Ok(())
    }

    fn send(&mut self, req: Request) -> Result<()> {
        self.send_recycling(req).map(|_| ())
    }
    fn send_recycling(&mut self, mut req: Request) -> Result<Option<Vec<u8>>> {
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(true));
        anyhow::ensure!(
            self.write_stream.is_none() || matches!(req, Request::WriteRange { .. }),
            "only range writes are valid during streaming writes"
        );
        anyhow::ensure!(
            self.read_stream.is_none()
                || matches!(
                    req,
                    Request::StopReadStream | Request::ShrinkReadStream { .. }
                ),
            "only stop and shrink requests are valid during a read stream"
        );
        if self.role != LocalConnectionRole::Control
            && matches!(
                &req,
                Request::TcpListen { .. }
                    | Request::DescriptorCopy(_)
                    | Request::ListDir { .. }
                    | Request::ListDirDetails { .. }
                    | Request::ListDirNoFollowFinal { .. }
                    | Request::NativeRemove { .. }
                    | Request::CheckOperatorDirectory { .. }
                    | Request::CheckOperatorDirectoryAncestry { .. }
                    | Request::RegisterSourceRoots { .. }
                    | Request::CreateOperatorDirectory { .. }
                    | Request::AnchorDestination { .. }
                    | Request::CopySmallFiles(_)
                    | Request::PruneLookup { .. }
                    | Request::Receipt
            )
        {
            self.pending.push_back(Response::Err(
                "request is allowed only on the control connection".into(),
            ));
            return Ok(None);
        }
        if self.role == LocalConnectionRole::SourceWorker && !req.allowed_on_source_worker() {
            self.pending.push_back(Response::Err(
                "request is not valid on a source worker".into(),
            ));
            return Ok(None);
        }
        match req {
            Request::ReadStream(stream) => {
                if self.role != LocalConnectionRole::SourceWorker || self.read_stream.is_some() {
                    self.pending.push_back(Response::Err(
                        "read stream requires an idle source worker".into(),
                    ));
                } else if let Err(error) = stream.validate() {
                    self.pending.push_back(Response::Err(error.to_string()));
                } else {
                    self.ops.begin_source_range(stream.off..stream.end);
                    self.read_stream_limit = stream.end;
                    self.read_stream_done_sent = false;
                    self.read_stream = Some(stream);
                    self.pending.push_back(Response::Ok);
                }
                return Ok(None);
            }
            Request::ShrinkReadStream { end } => {
                if self.read_stream.is_none() {
                    self.pending
                        .push_back(Response::Err("no read stream is active".into()));
                    return Ok(None);
                }
                crate::streaming::shrink_limit(&mut self.read_stream_limit, end)?;
                self.ops.shrink_source_range(end);
                return Ok(None);
            }
            Request::StopReadStream => {
                self.ops.end_source_range();
                if self.read_stream.take().is_none() {
                    self.pending
                        .push_back(Response::Err("no read stream is active".into()));
                } else if !self.read_stream_done_sent {
                    self.pending.push_back(Response::ReadStreamDone);
                }
                return Ok(None);
            }
            _ => {}
        }
        let resp = self.ops.handle_in_place(&mut req);
        if let Some(state) = &mut self.write_stream {
            state.record(resp);
        } else {
            self.pending.push_back(resp);
        }
        Ok(match req {
            Request::WriteRange { data, .. } => Some(data.into_vec()),
            _ => None,
        })
    }
    fn copy_local(
        &mut self,
        mut req: Request,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Response> {
        anyhow::ensure!(
            self.role == LocalConnectionRole::DestinationWorker
                && matches!(req, Request::CopyLocal { .. })
                && self.pending.is_empty()
                && self.read_stream.is_none()
                && self.write_stream.is_none(),
            "local copy requires an idle destination worker"
        );
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(true));
        Ok(self.ops.handle_with_copy_progress(&mut req, progress))
    }
    fn recv(&mut self) -> Result<Response> {
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(false));
        if self.pending.is_empty() {
            if let Some(stream) = &mut self.read_stream {
                if stream.off < self.read_stream_limit {
                    let response = self.ops.handle_in_place(&mut stream.next_request());
                    if let Response::Block { data, .. } = &response {
                        stream.off += data.len() as u64;
                    } else {
                        stream.off = stream.end;
                        self.ops.end_source_range();
                    }
                    return Ok(response);
                }
                // Match the server's early completion without pre-reading data
                // or adding a local producer thread. Stop still clears the
                // active mode, and never queues a second completion marker.
                if !self.read_stream_done_sent {
                    self.ops.end_source_range();
                    self.read_stream_done_sent = true;
                    return Ok(Response::ReadStreamDone);
                }
            }
        }
        self.pending
            .pop_front()
            .ok_or_else(|| anyhow!("no pending response"))
    }
    fn supports_request_pipelining(&self) -> bool {
        false
    }
    fn begin_streaming_writes(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.pending.is_empty() && self.write_stream.is_none(),
            "streaming writes require an idle connection"
        );
        self.write_stream = Some(crate::streaming::Completions::default());
        Ok(())
    }
    fn check_streaming_writes(&mut self) -> Result<()> {
        streaming_result(
            self.write_stream
                .as_ref()
                .context("no streaming writes are active")?
                .error
                .clone(),
        )
    }
    fn fence_streaming_writes(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.write_stream.is_some(),
            "no streaming writes are active"
        );
        Ok(())
    }
    fn finish_streaming_writes(&mut self, sent: u64, fence: Result<()>) -> Result<()> {
        let state = self
            .write_stream
            .take()
            .context("no streaming writes are active")?;
        fence?;
        anyhow::ensure!(
            state.count == sent,
            "streaming write completion count mismatch"
        );
        streaming_result(state.error)
    }
    fn scan(
        &mut self,
        root: &[u8],
        source: Option<&RegisteredPath>,
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        if let Some(source) = self.ops.source_scan_root(source)? {
            return crate::scan::scan_descriptor(
                source.root,
                &source.relative,
                source.expected_leaf,
                false,
                false,
                ignore,
                report_ignored,
                sink,
                ignored,
                warn,
            );
        }
        if let Some((destination_root, relative)) = self.ops.destination_scan_root(root)? {
            return crate::scan::scan_descriptor(
                destination_root,
                &relative,
                None,
                follow_root,
                true,
                ignore,
                report_ignored,
                sink,
                ignored,
                warn,
            );
        }
        let root = self.ops.scan_root(root)?;
        crate::scan::scan(
            &fsops::resolve(&root),
            follow_root,
            ignore,
            report_ignored,
            sink,
            ignored,
            warn,
        )
    }

    fn native_remove(
        &mut self,
        cwd: Option<&[u8]>,
        root: Option<&[u8]>,
        selections: &[NativeRemoveSelection],
        follow_symlinks: bool,
        dry_run: bool,
        workers: usize,
        trace: &mut dyn FnMut(Vec<String>) -> Result<()>,
        sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()> {
        if self.role != LocalConnectionRole::Control {
            bail!("native removal is allowed only on the control connection");
        }
        crate::native_rm::remove(
            cwd,
            root,
            selections,
            follow_symlinks,
            dry_run,
            workers,
            trace,
            sink,
        )
    }
}
