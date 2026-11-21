---
name: syq-rust-tests
description: Rules for syq Rust test fixtures - temporary directories, short socket paths, executable files, and background services. Use when writing or changing a Rust unit or integration test, or debugging a flaky test failure such as "Text file busy" or a leftover background service.
---

# syq Rust test fixtures

Rust fixtures use `test_support::tempdir()` or `test_support::temp_dir()`
from `tests/support/temp.rs` (re-exported by `src/test_support.rs` for unit
tests). These resolve the ambient temporary root before creating fixtures,
so macOS `/var` and other host symlinks do not become paths under test.
Create intentional symlinks inside that root; do not canonicalize product
arguments or add follow flags merely to make a fixture pass. For fixtures that
must fit Unix socket path limits, use `test_support::short_tempdir()`; it
centralizes the canonical short-root exception without changing `TMPDIR`.

Create any file that a test or the product code under test executes with
`write_executable` or `copy_executable` from `tests/support/executable.rs`.
They write it in a child process; a file the test process writes itself can
stay open in a process that another thread starts at that moment, so running
it fails with "Text file busy". Nextest gives each test its own process, but
plain `cargo test` shares one, and tests and product code also start
processes from several threads.

A test that starts a background service, such as `persist receive on`, must
stop it even when the test fails (for example with `PersistenceOff` in
`tests/local.rs`); deleting the test's temporary directory leaves the service
running.

Prefer exact or narrow filters in the `local` target (`tests/local.rs` holds
the shared helpers and `tests/local/<topic>.rs` the tests, named
`<topic>::<test>`); those tests invoke the built binary against temporary
trees.
