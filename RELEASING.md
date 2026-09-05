# Releasing syq

Releases are deliberately fail-closed: all four binaries, a matching signing
key, a protected release environment, and the Homebrew tap must be configured
before a tag can publish anything. The workflow uses a draft until every file
is uploaded and checked, then publishes it once. Enable GitHub's immutable
releases setting so published assets and tags cannot be changed afterward.

The Python SDK shares the version of the syq release it pins. JavaScript and Go
SDKs have independent versions, and every SDK has its own tag convention. Their
registry setup and release procedure live in [`sdk/RELEASING.md`](sdk/RELEASING.md).

## One-time repository setup

1. Rename the existing GitHub repository to `greaber/syq` and make it public;
   do not delete and recreate it. GitHub redirects old repository web and Git
   URLs after a rename. Create a public `greaber/homebrew-tap` repository; the
   formula will be written to `Formula/syq.rb` there.
2. Create a GitHub Actions environment named `release`. Add required reviewers
   and restrict deployments to release tags. Keep the default workflow token
   read-only; the workflow grants write permissions only to its release job.
3. Enable immutable releases, artifact attestations, branch protection for
   `master` without required status checks, dependency review/Dependabot, secret
   scanning, and a ruleset that restricts creation, update, and deletion of
   `v*` tags to release maintainers. GitHub's ruleset signature rule applies to
   commits, not annotated tag-object signatures; the release workflow checks
   the latter explicitly through GitHub's tag verification API.
   The repository's selected-actions policy permits GitHub-owned actions and
   the exact full-SHA
   `rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18`
   reference used by `release.yml`, while continuing to require full-SHA pins
   and deny verified actions generally. This narrow exception lets the release
   exchange GitHub OIDC identity for a crates.io credential without broadening
   the Actions trust boundary beyond the one official Rust action it needs.
4. Publish the first `syq` version to crates.io manually, then add a GitHub
   trusted publisher for repository `greaber/syq`, workflow `release.yml`, and
   environment `release`. Do not put a long-lived crates.io token in GitHub
   secrets. After the first automated publication succeeds, enable
   trusted-publishing-only mode on crates.io and revoke the bootstrap token.
5. The encrypted inventory initializer generates a dedicated SSH deploy key
   for `greaber/homebrew-tap`. The sync installs its public half on that
   repository with write access and places only its private half in the
   protected `release` environment. It has no access to the syq repository or
   to any other repository in the account.

## Encrypted release inventory

The committed `.env.release` file is the canonical release-credential
inventory. It contains ciphertext for `SYQ_RELEASE_SIGNING_KEY_PEM_B64` and
`HOMEBREW_TAP_DEPLOY_KEY`, plus the corresponding public
`SYQ_RELEASE_PUBLIC_KEY`. Its decryption authority lives only in the
gitignored `.env.keys`. Forks receive the ciphertext but neither the
decryption key nor official publishing authority.

Install the pinned maintainer tool, then initialize the inventory on an
encrypted developer machine. The initializer generates independent Ed25519
keys for manifest signing and Homebrew tap access; it needs no secret input.
The release scripts need `bash`, `jq`, `ssh-keygen`, and OpenSSL 3 as
`openssl` (1.1.1 cannot sign Ed25519 with `pkeyutl`); macOS ships LibreSSL
under that name, so install `openssl@3` with Homebrew and put its `bin`
directory first on `PATH` before signing:

```sh
npm install --global @dotenvx/dotenvx@2.21.0
scripts/init-release-secrets.sh
git add .env.release
git commit -m 'Add encrypted release credential inventory'
```

Back up `.env.keys` immediately in protected storage. Do not commit it, upload
it to GitHub, or use it in CI. Losing every copy prevents future releases from
using the signing identity embedded in installed clients.

After the repository has been renamed and the protected `release` environment
exists, preview and then synchronize the allowlisted values:

```sh
scripts/sync-github-secrets.sh
scripts/sync-github-secrets.sh --execute
gh secret list --repo greaber/syq --env release
gh variable list --repo greaber/syq
```

The sync sends the two individual private keys to environment secrets, installs
the Homebrew key's public half as a write-enabled deploy key on the tap, and
sends the release public key to the repository variable used by every official
build. It never sends `.env.keys`, any `DOTENV_PRIVATE_KEY_*` value, or an
undeclared entry from the encrypted file. It derives both public keys locally
and refuses a mismatched release signing pair or tap deploy key.

The Homebrew deploy key is already restricted to one repository and should not
need routine rotation. If it is exposed, replace its ciphertext with a newly
generated Ed25519 private key, remove the deploy key titled `syq release
workflow` from the tap, commit `.env.release`, and rerun the dry-run/execute
sync. The sync will install the new public half before updating the protected
environment secret.

Do not rotate the release signing key casually: installed clients trust it, so
a planned rotation first needs a release that trusts both old and new keys.

## Signing releases from the Linux server

GitHub authentication and tag signing use separate credentials. The server's
GitHub CLI login handles HTTPS pushes and API operations. The private SSH tag
signing key stays on the maintainer's Mac and is made available to a trusted
server session with SSH agent forwarding; it is never copied to the server,
the repository, the encrypted release inventory, or GitHub Actions.

Connect from the Mac with agent forwarding enabled for that session:

```sh
ssh -A user@host
```

On the server, confirm that the forwarded signing key is visible before
creating a tag. The expected fingerprint is public and can safely be checked
into this maintainer documentation:

```sh
ssh-add -l -E sha256 | grep -F 'SHA256:y3++huNJminuTLAOkyb635Vohfph9TfrzbtmVzM0dk0'
gh auth status
```

Configure each fresh clone once to use the public half of that forwarded key:

```sh
git config --local gpg.format ssh
git config --local user.signingkey \
  'key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIISayu4yojryfTmgi9qKUTlNkWkwNfVmA0GyVjbhHCQK'
git config --local tag.gpgSign true
```

Agent forwarding lets the server request signatures for the duration of the
connection, so enable it only for a trusted release host rather than globally.

## Cutting a release

1. Update the package version in `Cargo.toml`, run `cargo check` to refresh
   `Cargo.lock`, then run the normal locked checks to validate it. Write the
   curated introduction and breaking-change notes in
   `.github/release-notes/v<version>.md`; the release workflow prepends that
   file to GitHub's generated contributor and change list. Merge the version
   and release notes through the protected branch. Peer compatibility is
   the immutable release identity, so there is no separate protocol number to
   maintain. Native command changes must also be classified in
   `sdk/python/native-api.json`. A feature may use the `follow_up` disposition
   so its merge is not blocked on SDK work, but `scripts/check-python-api-sync.py`
   and the tag workflow refuse a release until every follow-up is resolved.
   Run `scripts/test-real-ssh.sh` as the local live-OpenSSH release check. It
   exercises all three coordinator placements across isolated source and
   destination containers and does not contact real remote hosts.

2. Once the release commit is the exact `master` tip, check for existing full
   validation on that commit before starting any more tests:

   ```sh
   candidate=$(git rev-parse master)
   scripts/verify-release-ci.sh greaber/syq "$candidate"
   ```

   A successful post-merge run is reusable. Each workflow records a
   `release-certification` job only when all its release suites were selected
   and passed. Green selective runs with skipped suites do not qualify. The
   verifier requires the latest push or manual run of each workflow on the
   exact SHA, from this repository's `master`, to succeed and carry that
   certificate in its current attempt. Runs made before certificates were
   introduced need a fresh manual run.

   If evidence is missing, dispatch only the workflow that needs it (both
   commands are shown here):

   ```sh
   gh workflow run ci.yml --ref master
   gh workflow run rsync-compat.yml --ref master
   ```

   If the latest run is still running, wait for it instead of starting a copy.
   A failed latest run must be investigated and repaired or rerun; an older
   success does not override it. Manual runs select every suite. After the
   needed runs succeed, repeat verification and run the read-only preflight:

   ```sh
   scripts/verify-release-ci.sh greaber/syq "$candidate"
   scripts/release-preflight.sh v0.1.9
   ```

   It requires the exact clean, synchronized `master` tip; no pending Python
   API follow-ups; matching Cargo metadata; successful `rust`, `sdks`,
   `macos`, `linux-arm64`, and `conformance` checks on that SHA; the two full-suite
   workflow certifications; an SSH tag-signing key registered with
   GitHub; the selected-Actions allowlist; the protected `release` environment,
   tag policy, variables, and secret names; and absence of the tag or version
   from GitHub, crates.io, and the Homebrew tap. It makes no local or remote
   changes. Then create and push a signed annotated tag matching the package
   version. Its signing key and email must be configured on your GitHub account
   so GitHub reports the tag-object signature as verified:

   ```sh
   git tag -s v0.1.0 -m 'syq 0.1.0'
   git push origin v0.1.0
   ```

3. Approve the protected `release` environment once. The same protected job
   publishes the release and updates Homebrew, so the deploy key is never
   exposed to an unapproved job and a second approval adds no distinct trust
   boundary. The workflow
   first verifies that the annotated tag's signature is valid and that it
   directly targets the workflow commit, that this commit is reachable
   from protected `master`, that the `rust`, `sdks`, `macos`, `linux-arm64`,
   and `conformance` checks all succeeded on that exact commit, and that both
   full-suite workflow certifications succeeded. It then builds
   static GNU Linux x86-64/ARM64
   binaries and native macOS Apple Silicon/Intel binaries, embeds an Ed25519
   signature over the manifest's RFC 8785 canonical JSON, verifies the exact
   asset inventory, creates provenance attestations, uploads a draft, checks
   every uploaded byte, publishes it, publishes the matching source package to
   crates.io with a short-lived OIDC credential, and finally updates the tap.
   Once the entire release workflow succeeds, the Python SDK preparation
   workflow opens a pull request for the matching SDK release using this
   immutable syq manifest. PyPI publication remains a separate signed-tag and
   protected-environment action, so a registry outage cannot block syq.
   Track the complete state at any time with:

   ```sh
   scripts/release-status.sh v0.1.9
   scripts/release-status.sh --json v0.1.9
   ```

   The report correlates the exact tag commit, release runs and pending
   environments, GitHub release state, crates.io, the matching PyPI SDK version,
   and the Homebrew formula without modifying any of them.
4. Verify one or more downloaded artifacts and exercise all install paths:

   ```sh
   gh attestation verify syq-linux-x86_64 --repo greaber/syq
   curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh -o install.sh
   less install.sh
   sh install.sh --bin-dir "$(mktemp -d)"
   brew install greaber/tap/syq
   cargo install --locked syq --root "$(mktemp -d)"
   ```

If a job stops after creating a draft, inspect that draft rather than
overwriting it. The workflow refuses to reuse drafts. It may safely be rerun
after a fully published release: it downloads every published asset and
requires byte-for-byte equality with the rebuilt release before forwarding the
formula to the tap job. The same rerun packages the source crate again and
requires its SHA-256 to match the immutable crates.io version; a missing
version is published, while a divergent version fails closed.

### Failed tag cleanup and the permanence boundary

A pushed tag is provisional until the release reaches permanent published
state. If an attempt is abandoned before then, do not burn the version merely
because the tag existed: verify that no GitHub release, package-registry
version, Homebrew update, module-proxy entry, or durable attestation exists,
clean any recoverable draft, and delete the exact local and remote tag refs.
Never force-update the tag. Once the cause is fixed, a maintainer may create a
new signed tag for the still-unpublished version from a fully checked `master`
commit.

Once any permanent destination accepts the version, the tag is immutable even
if later publication steps fail. Do not delete or move it. Rerun the idempotent
steps from the same tag when their checks permit it; otherwise repair the
remaining channel without changing published bytes or advance to a new
version. Record the exact tag object, target commit, failed workflow, and every
destination checked whenever deciding which side of this boundary an attempt
is on.

The release workflow sets `SYQ_RELEASE_BUILD=1`, which makes each platform
binary report the tag (for example `v0.2.0`) as its build identity. Ordinary
source builds instead include their Git revision and cannot populate the
managed remote-helper cache. Release manifests and binaries use the release tag
as their sole release identity.

## CI scope

Pull requests do not start automated test or documentation workflows, and
branch protection does not require test status contexts. The working agent runs
the proportionate local checks described in `AGENTS.md` and reports exactly
what was verified. A merge does not wait for GitHub to repeat those checks.

Every native push to `master` runs the complete native and SDK suites, Linux
and macOS conformance, Linux ARM64 validation, focused Apple Silicon macOS
tests, and an Intel macOS compile-and-updater check. The separate macOS workflow
also runs the complete native and SDK suites on Apple Silicon. Each run has a
unique concurrency group, including while it is pending, because a later push
may affect a different subsystem and therefore cannot safely replace the
earlier push's selected suites. Failures are repaired in follow-up changes; they
do not retroactively gate unrelated merges. A release candidate must still have
successful, exact-SHA full-suite certificates from both workflows. Release
preflight and tag verification require the stable `rust`, `sdks`, `linux-arm64`, `macos`, and
`conformance` evidence names and reject selective stubs.

The checked-in classifier uses each push's exact diff. Documentation-only
changes select no test jobs unless a document is consumed by a test or
generator. Unknown paths fail safe by selecting every affected suite. Manual
workflow runs select everything. Documentation site checks and deployment also
happen only after a relevant change reaches `master`, or on manual dispatch.

## macOS signing

The supported install paths use terminal download tools or Homebrew, which
normally do not set `com.apple.quarantine`; unsigned command-line binaries
therefore do not normally trigger the warning seen for browser downloads. The
current workflow does not hold an Apple Developer credential. If syq later
offers browser downloads as a primary path, add Developer ID signing and Apple
notarization in the macOS build jobs before advertising that path.
