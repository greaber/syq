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
4. Give a fine-grained token write access only to the contents of
   `greaber/homebrew-tap`. Store it as the `HOMEBREW_TAP_TOKEN` secret in the
   `release` environment. It does not need access to the syq repository.

Create the Ed25519 release key offline on an encrypted machine and retain a
protected backup:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out syq-release-signing.pem
public_key=$(openssl pkey -in syq-release-signing.pem -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
gh variable set SYQ_RELEASE_PUBLIC_KEY --body "$public_key"
base64 < syq-release-signing.pem | tr -d '\n' | gh secret set SYQ_RELEASE_SIGNING_KEY_PEM_B64 --env release
```

`SYQ_RELEASE_PUBLIC_KEY` is a repository variable because every official target
embeds it. The private-key value is an environment secret available only after
release approval. CI derives the public key from the private key and refuses to
publish if they differ. Do not rotate this key casually: installed clients
trust it, so a planned rotation first needs a release that trusts both old and
new keys.

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
