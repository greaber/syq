# Releasing syq

Releases are deliberately fail-closed: all four binaries, a matching signing
key, a protected release environment, and the Homebrew tap must be configured
before a tag can publish anything. The workflow uses a draft until every file
is uploaded and checked, then publishes it once. Enable GitHub's immutable
releases setting so published assets and tags cannot be changed afterward.

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
4. The encrypted inventory initializer generates a dedicated SSH deploy key
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

## Rename cutover with active worktrees

Treat the code rename and the GitHub repository rename as one coordinated
cutover, after functional branches that still use `pcp` have merged:

1. Merge ready in-progress feature branches into `master` while the code still
   uses the old name. Rebase this distribution branch onto that result and land
   its mechanical `pcp`-to-`syq` rename once.
2. Immediately rename `greaber/pcp` to `greaber/syq` in GitHub settings, as the
   second half of the same cutover. Do not later create another `greaber/pcp`,
   because that disables GitHub's old-URL redirect.
3. From the primary checkout, run
   `git remote set-url origin https://github.com/greaber/syq.git`. The remote
   configuration is shared by all linked worktrees, so do this only once.
4. Rebase any feature branch that must remain open onto the renamed `master`.
   It then resolves the naming change once, rather than making every worktree
   carry an independent partial rename.

The local `/home/grant/repos/pcp` directory name is cosmetic. Do not move it
while linked worktrees exist, because Git records their paths. If changing the
directory name matters, remove completed linked worktrees first and make a
fresh clone at `/home/grant/repos/syq`; otherwise leaving the directory named
`pcp` has no user-visible effect.

## Cutting a release

1. Update the package version in `Cargo.toml`, run `cargo check` to refresh
   `Cargo.lock`, then run the normal locked checks to validate it. Update
   release notes and merge through the protected branch. Change the protocol
   version in `src/proto.rs` only for a wire-incompatible release.
2. Create and push a signed annotated tag matching the package version. Its
   signing key and email must be configured on your GitHub account so GitHub
   reports the tag-object signature as verified:

   ```sh
   git tag -s v0.1.0 -m 'syq 0.1.0'
   git push origin v0.1.0
   ```

3. Approve the protected `release` environment. The workflow first verifies
   that the annotated tag's signature is valid and that it directly targets
   the workflow commit, and that this commit is reachable from protected
   `master`. It then builds static GNU Linux x86-64/ARM64 binaries and native
   macOS Apple Silicon/Intel binaries, signs the manifest, verifies the exact
   asset inventory, creates provenance attestations, uploads a draft, checks
   every uploaded byte, publishes it, and finally updates the tap.
4. Verify one or more downloaded artifacts and exercise both install paths:

   ```sh
   gh attestation verify syq-linux-x86_64 --repo greaber/syq
   curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh -o install.sh
   less install.sh
   sh install.sh --bin-dir "$(mktemp -d)"
   brew install greaber/tap/syq
   ```

If a job stops after creating a draft, inspect that draft rather than
overwriting it. The workflow refuses to reuse drafts. It may safely be rerun
after a fully published release: it downloads every published asset and
requires byte-for-byte equality with the rebuilt release before forwarding the
formula to the tap job.

## macOS signing

The supported install paths use terminal download tools or Homebrew, which
normally do not set `com.apple.quarantine`; unsigned command-line binaries
therefore do not normally trigger the warning seen for browser downloads. The
current workflow does not hold an Apple Developer credential. If syq later
offers browser downloads as a primary path, add Developer ID signing and Apple
notarization in the macOS build jobs before advertising that path.
