# Released completion wire fixtures

These postcard payloads were generated from unchanged `src/proto.rs` at tag
`v0.3.2` (source SHA-256
`391c241ff35c09573d1fae54a7ee1bb292382a8256f83756e82c3381d5ba2d9f`).
They exclude the connection preamble. The request lists `/data`, prefix `al`,
limit 1000, no confined root, and refuses symlinks. The response contains one
nondirectory entry named `alpha`, without truncation.

The compatibility test reads and re-encodes these unchanged payloads. New detail
requests and responses were appended to the enums; existing tags and fields
remain unchanged. Actual helper connections still require matching build
identities before decoding messages. A mismatched explicit helper is rejected;
use the matching helper or the managed helper installation to recover.

Completion endpoint cache and persistence preference formats are unchanged.
Old shell adapters continue to request name-only output from a new binary.
Reload generated shell adapters when changing binary versions.
