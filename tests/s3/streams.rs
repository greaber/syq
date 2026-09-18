//! Fault and descriptor tests use an independent loopback HTTP fixture.
use std::process::Command;

fn scenario(name: &str) {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/object-storage/stream-faults.py"
        ))
        .arg(env!("CARGO_BIN_EXE_syq"))
        .arg(name)
        .output()
        .expect("run local stream fixture");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn ordered_ranges_and_inherited_output() {
    scenario("download");
}
#[test]
fn truncated_ranges_retry_without_duplicate_output() {
    scenario("retry");
}
#[test]
fn bad_ranges_and_changed_objects_fail() {
    scenario("bad-range");
}
#[test]
fn stream_uploads_publish_only_complete_input() {
    scenario("upload");
}
#[test]
fn failed_parts_abort_multipart_upload() {
    scenario("upload-error");
}
#[test]
fn quiet_input_and_blocked_output_cancel() {
    scenario("cancel");
}
#[test]
fn invalid_descriptors_and_broken_pipes_fail() {
    scenario("descriptors");
}

#[test]
fn truncated_range_failure_is_not_success() {
    scenario("truncated");
}
#[test]
fn upload_retries_replay_buffered_parts() {
    scenario("upload-retry");
}
