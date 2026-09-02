# Releasing the language SDKs

SDK releases use independent versions and tags. Published versions are
immutable: never move or delete their release tags or attempt to replace an
uploaded package. A Python or JavaScript tag whose publication is abandoned
before any permanent release or registry state exists remains provisional;
audit all destinations, clean any recoverable draft, and delete that tag rather
than burning an unpublished SDK version.

A Go module tag such as `sdk/go/v*` is permanent as soon as it is pushed. The
tag itself publishes the version: a client or arbitrary module proxy may fetch
and cache it before the documented `proxy.golang.org` request. That publication
cannot be fully audited, and deleting or recreating the tag can leave clients
with conflicting authenticated content. Never delete, recreate, or move a Go
module tag.

## One-time setup

### PyPI

The repository already has a protected GitHub environment named `pypi`. It
requires maintainer approval and accepts only `sdk-python-v*` tags. In the
existing PyPI account, create a pending GitHub trusted publisher with:

- PyPI project name: `syq`
- GitHub owner: `greaber`
- GitHub repository: `syq`
- workflow: `publish-sdks.yml`
- environment: `pypi`

The pending publisher is the remaining account-side setup. It does not reserve
the name; the first successful workflow run creates the project.

### npm

In the existing npm account, create the free organization `syq` for unlimited
public packages. Require two-factor authentication for the organization and
add a second trusted maintainer when one is available.

npm cannot configure a trusted publisher until the package exists. The first
release therefore requires `npm login` and one local publish from a clean,
reviewed `master` checkout:

```sh
cd sdk/js
npm ci
npm test
npm pack --dry-run
npm publish --access public
```

After `@syq/sdk` exists, configure its GitHub Actions trusted publisher with:

- organization or user: `greaber`
- repository: `syq`
- workflow: `publish-sdks.yml`
- environment: `npm`
- allowed action: `npm publish`

Create a protected GitHub environment named `npm`, require approval, and
restrict it to `sdk-js-v*` release tags. Future releases use OIDC and need no
long-lived npm token in GitHub.

### Go

Go has no publisher account or central name reservation. The module path in
`go/go.mod` and an immutable Git tag identify the module. Publishing the first
tag commits the project to `github.com/greaber/syq/sdk/go`; changing to a
future vanity domain would create a different Go module.

The repository's release-tag ruleset restricts creation, update, deletion, and
non-fast-forward changes for `sdk-python-v*`, `sdk-js-v*`, and `sdk/go/v*` tags
to the release maintainer, alongside the existing `v*` protection. Like binary
releases, every SDK release uses a signed annotated tag whose signature GitHub
recognizes.

## Release checks

Update exactly one package version, merge it through the normal protected
branch workflow, and run all SDK checks. Create a signed annotated tag that
directly targets the commit on `master`.

For a Python release, first choose the exact immutable syq release the SDK will
use. Replace `python/src/syq/syq-release-manifest.json` with that release's
complete signed manifest; do not edit its artifact hashes by hand. Update the
mapping table in `README.md`. The packaged manifest is the SDK's immutable
executable-version mapping and runtime trust root for downloaded bytes. Tests
and the release workflow must build the wheel in a clean cache, perform its
managed first-use download, and require `syq.version()` to equal
`syq.PINNED_SYQ_VERSION`.

Python tags use the version in `python/pyproject.toml`:

```sh
git tag -s sdk-python-v0.0.1 -m 'Python SDK 0.0.1'
git push origin sdk-python-v0.0.1
```

The first Python tag uses the pending trusted publisher configured above; do
not upload `0.0.1` locally. The protected workflow creates the PyPI project and
publishes the already-tested distributions with OIDC. PyPI does not reserve the
name until that workflow successfully publishes, so create the pending
publisher immediately before the tag.

JavaScript `0.0.1` is the package that requires the manual bootstrap publish.
After those exact bytes are verified and its trusted publisher is configured,
subsequent JavaScript tags use the version in `js/package.json` normally:

```sh
git tag -s sdk-js-v0.0.1 -m 'JavaScript SDK 0.0.1'
git push origin sdk-js-v0.0.1
```

Those tags run `.github/workflows/publish-sdks.yml`, which verifies that the
signed tag targets a `master` commit whose `sdks` check passed, then verifies
the version, tests, package contents, pinned download, and executable identity
before entering the protected publishing environment.

## Automated Python follow-up to a syq release

The `sdks` CI job builds the syq executable from the commit under test and runs
the Python adapter's candidate compatibility tests against it. These exercise
the reported version, a real disposable local copy, argument boundaries, and
failure retention. The syq release tag verifier requires `sdks` alongside the
Rust and platform checks, so a failing adapter blocks publication of the syq
release itself. The same job requires the packaged Python manifest to match the
latest immutable syq release. Until the generated mapping pull request lands,
subsequent development therefore cannot acquire a green release-eligible
`sdks` check or consume the same next Python patch version.

After `.github/workflows/release.yml` completes successfully and the GitHub
release is immutable, `.github/workflows/prepare-python-sdk.yml` downloads its
exact signed manifest and prepares the next Python patch version. It opens an
`automation/python-sdk-vX.Y.Z` pull request containing the version, manifest,
cache-path documentation, lockfile, and mapping-table updates. GitHub places
pull-request workflow runs caused by its own token into an approval-required
state. The preparation workflow waits until GitHub has registered both native
runs for the exact generated commit, verifies that the pull request and native
events belong to the trusted repository, then approves them through the
Actions API so the required checks remain attached to the pull request. The
fixture-tested helper has a bounded deadline and reports its last observed
state on failure. Once the runs exist, the workflow requests auto-merge; GitHub
still waits for every required check and branch-protection rule. The repository
keeps the default workflow token read only, permits trusted Actions workflows
to create pull requests, and grants write scopes only inside this preparation
workflow.

The generated pull request merges automatically after its required checks.
Reviewers may still stop auto-merge while it is pending. The final publication
remains a deliberate release-authority action: create the signed annotated
`sdk-python-v<version>` tag and approve the protected `pypi` environment. The
tag then publishes through OIDC without a local upload or long-lived PyPI
credential. Keeping the tag signature manual avoids placing maintainer signing
authority in CI. The additional PyPI environment approval is intentionally
retained as defense in depth for a separate package registry; PyPI availability
cannot block publication of syq itself.

Python distributions use a pinned interpreter and the tagged commit timestamp
as `SOURCE_DATE_EPOCH`, and the source archive is repacked with normalized
metadata. CI compares two separate builds byte for byte. This makes a full
workflow rerun safe even when the first run partly reached PyPI and its
short-lived GitHub artifact has expired: rebuilding the same tag produces the
same immutable files.

Because the Go module lives below the repository root, its tag must include
the module directory:

```sh
cd sdk/go
go mod tidy
go test ./...
cd ../..
git tag -s sdk/go/v0.0.1 -m 'Go SDK 0.0.1'
git push origin sdk/go/v0.0.1
GOPROXY=https://proxy.golang.org go list -m \
  github.com/greaber/syq/sdk/go@v0.0.1
```

The final command asks the public Go proxy to fetch the tagged module. It then
becomes discoverable through `pkg.go.dev`; no separate upload is performed.
