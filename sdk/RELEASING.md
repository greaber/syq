# Releasing the language SDKs

SDK releases use independent versions and tags. Published versions are
immutable: never move a release tag or attempt to replace an uploaded package.

## One-time setup

### PyPI

In the existing PyPI account, create a pending GitHub trusted publisher with:

- PyPI project name: `syq`
- GitHub owner: `greaber`
- GitHub repository: `syq`
- workflow: `publish-sdks.yml`
- environment: `pypi`

Create a protected GitHub environment named `pypi`, require a maintainer's
approval, and restrict it to `sdk-python-v*` release tags. A pending publisher
does not reserve the name; the first successful workflow run creates the
project.

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

Extend the repository's release-tag ruleset to restrict creation, update, and
deletion of `sdk-python-v*`, `sdk-js-v*`, and `sdk/go/v*` tags to release
maintainers. Like binary releases, every SDK release uses a signed annotated
tag whose signature GitHub recognizes.

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

After the manually published `0.0.1` package is byte-for-byte verified, create
its tag and configure trusted publishing. Subsequent JavaScript tags use the
version in `js/package.json` normally:

```sh
git tag -s sdk-js-v0.0.1 -m 'JavaScript SDK 0.0.1'
git push origin sdk-js-v0.0.1
```

Those tags run `.github/workflows/publish-sdks.yml`, which verifies the tag,
version, tests, package contents, pinned download, and executable identity
before entering the protected publishing environment.

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
