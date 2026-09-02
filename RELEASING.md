# Releasing syq

Releases are deliberately fail-closed: all four binaries, a matching signing
key, a protected release environment, and the Homebrew tap must be configured
before a tag can publish anything. The workflow uses a draft until every file
is uploaded and checked, then publishes it once. Enable GitHub's immutable
releases setting so published assets and tags cannot be changed afterward.

Python, JavaScript, and Go SDKs have independent versions and tag conventions.
Their registry setup and release procedure live in [`sdk/RELEASING.md`](sdk/RELEASING.md).

## One-time repository setup

1. Rename the existing GitHub repository to `greaber/syq` and make it public;
   do not delete and recreate it. GitHub redirects old repository web and Git
   URLs after a rename. Create a public `greaber/homebrew-tap` repository; the
   formula will be written to `Formula/syq.rb` there.
2. Create a GitHub Actions environment named `release`. Add required reviewers
   and restrict deployments to release tags. Keep the default workflow token
   read-only; the workflow grants write permissions only to its release job.
3. Enable immutable releases, artifact attestations, branch protection for
   `master`, required `ci` checks, dependency review/Dependabot, secret
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
keys for manifest signing and Homebrew tap access; it needs no secret input:

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
   `Cargo.lock`, then run the normal locked checks to validate it. Update
   release notes and merge through the protected branch. Peer compatibility is
   the immutable release identity, so there is no separate protocol number to
   maintain.
2. Wait for the post-merge `ci` run on `master` to succeed for the release
   commit. Pull requests are checked against their own head rather than the
   merged result, and the release workflow refuses a commit whose `rust`,
   `sdks`, `macos`, and `linux-arm64` checks have not all succeeded. The `sdks`
   check builds the candidate syq and exercises it through the Python adapter,
   so tagging a red or still-running `master` only produces a failed release
   run:

   ```sh
   gh run watch --exit-status "$(gh run list --workflow ci.yml --branch master --commit "$(git rev-parse master)" --json databaseId --jq '.[0].databaseId')"
   ```

   Then create and push a signed annotated tag matching the package version.
   Its signing key and email must be configured on your GitHub account so
   GitHub reports the tag-object signature as verified:

   ```sh
   git tag -s v0.1.0 -m 'syq 0.1.0'
   git push origin v0.1.0
   ```

3. Approve the protected `release` environment for the publishing job, then
   approve it again when the separate Homebrew tap job is ready. The workflow
   first verifies that the annotated tag's signature is valid and that it
   directly targets the workflow commit, that this commit is reachable
   from protected `master`, and that the `rust`, `sdks`, `macos`, and
   `linux-arm64` checks all succeeded on that exact commit. It then builds
   static GNU Linux x86-64/ARM64
   binaries and native macOS Apple Silicon/Intel binaries, embeds an Ed25519
   signature over the manifest's RFC 8785 canonical JSON, verifies the exact
   asset inventory, creates provenance attestations, uploads a draft, checks
   every uploaded byte, publishes it, publishes the matching source package to
   crates.io with a short-lived OIDC credential, and finally updates the tap.
   Once the entire release workflow succeeds, the Python SDK preparation
   workflow opens a pull request for the next SDK patch release using this
   immutable syq manifest. PyPI publication remains a separate signed-tag and
   protected-environment action, so a registry outage cannot block syq.
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

The release workflow sets `SYQ_RELEASE_BUILD=1`, which makes each platform
binary report the tag (for example `v0.2.0`) as its build identity. Ordinary
source builds instead include their Git revision and cannot populate the
managed remote-helper cache. The manifest's `helper_id: v<release>-p0` and the
binary's `--remote-helper-id` output are deprecated compatibility shims for
updaters through 0.1.1; `p0` is fixed and must not be treated or bumped as a
protocol version.

## macOS signing

The supported install paths use terminal download tools or Homebrew, which
normally do not set `com.apple.quarantine`; unsigned command-line binaries
therefore do not normally trigger the warning seen for browser downloads. The
current workflow does not hold an Apple Developer credential. If syq later
offers browser downloads as a primary path, add Developer ID signing and Apple
notarization in the macOS build jobs before advertising that path.
