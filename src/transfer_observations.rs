//! Measured waits, with units and observation points kept explicit.
//! These totals do not identify a bottleneck by themselves: source-response
//! waits include transport, and destination-send waits can reflect a slow
//! receiver. Different workers overlap, so their totals are not a partition
//! of elapsed transfer time.

#[derive(Default)]
pub(crate) struct WorkerWaits {
    pub source_response_seconds: f64,
    pub destination_send_seconds: f64,
    pub destination_ack_seconds: f64,
    pub scheduling_seconds: f64,
}

/// Request handling includes validation, hashing and filesystem work. It is
/// deliberately distinct from the time spent inside source/destination I/O.
#[derive(Default)]
pub(crate) struct ServerTimings {
    pub request_wait_seconds: f64,
    pub handling_seconds: f64,
    pub response_send_seconds: f64,
}
