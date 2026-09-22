//! Fault and descriptor tests use an independent loopback HTTP fixture.
use crate::process::CommandExt as _;
use std::process::Command;

fn scenario(name: &str) {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/object-storage/stream-faults.py"
        ))
        .arg(env!("CARGO_BIN_EXE_syq"))
        .arg(name)
        .capture_output()
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

#[test]
fn descriptor_flags_survive_cancellation_and_forced_exit() {
    scenario("descriptor-flags");
}
#[test]
fn environment_options_apply_to_streams() {
    scenario("environment-options");
}

#[test]
fn named_pipes_and_process_substitution_upload() {
    scenario("pipe-sources");
}

#[test]
fn managed_streams_commit_only_after_producer_success() {
    scenario("managed-commit");
}

#[test]
fn stream_previews_inspect_without_transferring_payload() {
    scenario("preview-results");
}

#[test]
fn size_filters_select_without_consuming_input() {
    scenario("size-filters");
}

#[test]
fn file_descriptors_preserve_metadata_and_skip_newer_objects() {
    scenario("file-metadata");
}
