# Compatibility and upgrades

Audit of master `930fa04`, 2026-09-05. This is a maintainer design note, not a
public support promise. The user reports no users yet and wants upgrade hazards
recognized before implementation. Earlier deliberate breaks are not being
retroactively treated as bugs. The release that starts compatibility support,
the support window, and the downgrade policy remain decisions to make.

## Main finding

Keep one implementation where possible, but distinguish same-build messages
from things that survive a build. Exact helper selection and the wire preamble
are useful existing protection. They do not preserve installed enrollments,
user settings, saved results, command scripts, or old updaters. Adding a version
number everywhere would not solve those upgrade paths either.

## Inventory

| Boundary and source | Current mechanism | Upgrade consequence and evidence to add |
| --- | --- | --- |
| Live helper protocol: `src/proto.rs`, `src/identity.rs`, `build.rs`, `src/remote_helper.rs` | Fixed bounded preamble checks exact build identity before postcard decoding; official helpers use release-specific cache paths. | Preserve early mismatch rejection and old/new helper coexistence. Keep captured old preambles. An internal enum change need not support mixed builds if every entry path enforces the gate. |
| Restricted receiver installation and enrollment: `src/restricted.rs` | `CONFIG_VERSION = 3` gates local and remote JSON state. Enrollment replaces the shared `~/.local/libexec/syq-receiver` executable. Local key is `enrollment-key`. | A new enrollment can replace the executable used by old enrollments. Test old client after new enrollment on the same account, plus new client with old local and remote state. A config generation bump alone does not provide coexistence. |
| Signed grants and replay protection: `src/delegation.rs`, `src/restricted.rs` | Canonical binary grant and signing namespace; durable `redeemed-*` records. `run_receiver` verifies and redeems before entering the server handshake. | Trace this boundary separately from the wire preamble. Never reinterpret old signed bytes with new authority semantics. Preserve replay rejection across upgrades and rollback while grants remain valid. Test a previously redeemed, still-valid grant after upgrade. |
| Receipts: `src/receipt.rs` | Magic bytes, canonical postcard body, signature namespace, HPKE context; no independent format version. Detached output can survive the connection. | Decide whether saved receipts need future verification, and with which tool. If so, retain a format discriminator or an authenticated producer identity and a supported verification route. Freeze signed byte fixtures; same-build round trips are insufficient. |
| Resume: `src/resume.rs`, `src/transfer.rs`, `src/fsops.rs` | Stable identity format, serialized semantic flags, hash-derived copy ID and adjacent partial filenames; an existing test freezes an identity and digest. | Include upstream flag serialization and filename derivation in the contract. Test interrupt with the baseline binary, resume with the candidate, and verify content. A safe restart may lose progress; report that separately from data safety. |
| Persistence preferences and live scopes: `src/persistence.rs` | Unversioned `persistence.json`, strict JSON fields, `.syq-persistence` marker, OpenSSH control connections. | Durable user preference is not a disposable cache. Define migration or rejection for format changes, and test old/new processes sharing scopes without losing the ability to close owned connections. |
| Tuning and completion caches: `src/tune.rs`, `src/completion.rs` | Unversioned JSON cache files. | These can generally be rebuilt. Test incompatible cache handling and safe defaults; use a generation only when needed to prevent stale interpretation. Do not extend that rationale to enrollment keys or preferences. |
| Automation output: `src/results.rs`, `schemas/automation.schema.json`, `docs/automation.md` | `schema_version = 1`; documented stable required fields and meanings; optional fields and record types can be added. Current fixtures validate current producers. | Preserve historical fixtures separately from regeneratable examples. Test new decoders on old streams and baseline decoders on candidate streams where compatibility is promised. Semantic changes can pass JSON Schema validation. |
| CLI, mappings and SDK APIs: `src/cli.rs`, `sdk/python/native-api.json`, `sdk/python/src/syq/`, `sdk/go/client.go`, `docs/reference.md`, `docs/mappings.md` | CLI grammar, exit behavior, Python typed API and pinned managed binary; Go process wrapper can select an executable. | SDK binary pinning does not protect application code upgrading the SDK, or scripts using PATH. Freeze representative invocations, mapping bytes, result behavior and Python calls. Include changes in defaults, path selection, deletion and partial-success meaning, not just removed names. |
| Distribution and updating: `src/update.rs`, `RELEASING.md`, `sdk/python/src/syq/managed.py` | Signed release manifest with `ed25519-jcs-v1`, embedded verification key, release assets and Python binary pin. | Old updaters must verify future release metadata. Test candidate manifests with the baseline verifier and plan key rotation before replacing the sole trusted key. Test without publishing or replacing real installations. |
| Published links and schema identity: `docs/`, `schemas/automation.schema.json` | mdBook pages and schema `$id` have public paths. | Renaming files can break external references while all repository links pass. Preserve redirects or stable aliases once those paths are supported. |

## Recent changes that illustrate the boundaries

GitHub returned no review bodies for these PRs. These examples come from their
PR descriptions and current code, not reconstructed reviewer quotations:

- [#192](https://github.com/greaber/syq/pull/192) renamed the local key file and
  replay records as part of a vocabulary cleanup. Its statement that old grants
  expire within 24 hours does not itself establish that all grants have expired
  at upgrade time. An actual rollout must account for still-valid grants.
- [#195](https://github.com/greaber/syq/pull/195) removed wire format versions,
  signing-domain suffixes and state-file generations. Its same-build premise
  applies to gated live exchanges; persistence preferences and installed
  receiver state have different lifetimes.
- [#189](https://github.com/greaber/syq/pull/189) changed signed deadline fields
  while leaving the grant version unchanged, and removed a CLI option and
  Python keyword. That spans authorization, command scripts and SDK source
  compatibility, each with a different consumer.
- [#188](https://github.com/greaber/syq/pull/188) and
  [#190](https://github.com/greaber/syq/pull/190) deliberately removed old CLI
  spellings and SDK keywords. With a supported baseline, those require aliases,
  a migration, or an explicitly scheduled break.
- [#186](https://github.com/greaber/syq/pull/186) changed a published docs URL and
  schema `$id` without changing the event schema version. File renaming is not
  evidence that the external contract stayed the same.
- [#159](https://github.com/greaber/syq/pull/159) is a useful model: it added an
  early build gate and captured old-format coverage, so mismatch diagnosis
  happens before incompatible enum decoding.

## Proposed launch work, in priority order

1. Choose the first supported release and an upgrade promise. A practical
   starting point is testing each candidate against the previous supported
   public release, while keeping older fixtures for any longer-lived contracts
   still promised. Do not assume package version `0.x` decides what survives.
2. Resolve receiver coexistence. Evaluate release-specific receiver executables
   referenced by each enrollment, or a stable dispatcher with explicit routing.
   Preserve enrollment identity, revocation and replay protection. Include two
   clients sharing one receiver account and an upgrade during an active copy.
   Choose one design after evaluating lifecycle and cleanup; this audit does
   not implement either proposal.
3. Establish immutable compatibility fixtures with provenance: release/tag,
   exact commit, producer command, target where relevant, and expected behavior.
   Start with enrollment/replay state, resume identities, automation streams,
   and release manifests. Use synthetic test keys and disposable directories.
   Keep these apart from `regen-automation-fixtures.sh` output.
4. Add focused upgrade tests using a pinned baseline binary and the candidate.
   Cover new reads old, old runs after new, and coexistence only where those
   directions are supported. Unsupported cases must reject safely and explain
   recovery; rejection is not equivalent to a seamless upgrade.
5. Run the relevant compatibility tests before review and include the full
   upgrade matrix in release preflight. PRs currently do not run automated test
   workflows, so adding a CI job alone would not catch mistakes before review.

## Making this visible to agents

The `AGENTS.md` checklist makes the boundary assessment part of implementation.
For affected work, a short PR paragraph should say:

> Compatibility: [boundary]; baseline [release and SHA]; [preserve / migrate /
> invalidate cache / reject]; checked [direction and fixture/test]; authorized
> break or remaining limitation [if any].

A later changed-file check can point agents to the inventory and relevant
fixtures. Treat it as a reminder, not proof: a filename matcher cannot tell
whether a default changed meaning or whether signed authority widened. The
stronger mechanical checks execute unchanged baseline inputs against the new
code. Do not satisfy them by regenerating the baseline in the same change.

No runtime behavior, format, compatibility test harness, or public support
policy is changed by this audit. The immediate deliverable is the inventory
and agent guidance; the launch work above remains proposed.
