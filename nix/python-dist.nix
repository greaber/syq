{ pkgs, root, epoch }:
let
  inherit (pkgs) lib;
  pin = builtins.fromJSON (builtins.readFile (root + /sdk/python/native-source.json));
  sdkManifest = builtins.fromTOML (builtins.readFile (root + /sdk/python/pyproject.toml));
  releaseManifest = builtins.fromJSON (builtins.readFile (root + /sdk/python/src/syq/syq-release-manifest.json));
  nativeSource = builtins.fetchTree {
    type = "github";
    owner = "greaber";
    repo = "syq";
    inherit (pin) rev narHash;
  };
  nativeManifest = builtins.fromTOML (builtins.readFile "${nativeSource}/Cargo.toml");
  toolchain = pkgs.rust-bin.fromRustupToolchainFile "${nativeSource}/rust-toolchain.toml";
  rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
  sdkSource = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [ (root + /sdk/python) (root + /scripts/stage-python-sdk.py) ];
  };
  source = pkgs.runCommand "syq-python-source" { nativeBuildInputs = [ pkgs.python313 ]; } ''
    python ${sdkSource}/scripts/stage-python-sdk.py --root ${sdkSource} --out "$out" \
      --native-source ${nativeSource} --native-revision ${pin.rev}
  '';
  platform = {
    x86_64-linux = "linux-x86_64";
    aarch64-linux = "linux-aarch64";
    x86_64-darwin = "macos-x86_64";
    aarch64-darwin = "macos-arm64";
  }.${pkgs.stdenv.hostPlatform.system};
  archive = releaseManifest.artifacts.${platform}.archive;
  nativeArchive = pkgs.fetchurl {
    url = "https://github.com/greaber/syq/releases/download/${releaseManifest.tag}/${archive.name}";
    sha256 = archive.sha256;
  };
  lock = builtins.fromTOML (builtins.readFile (root + /sdk/python/uv.lock));
  maturinSpec = lib.findFirst (p: p.name == "maturin") null lock.package;
  wheelTag = {
    x86_64-linux = "manylinux_2_12_x86_64";
    aarch64-linux = "manylinux_2_17_aarch64";
    x86_64-darwin = "macosx_10_12_universal2";
    aarch64-darwin = "macosx_10_12_universal2";
  }.${pkgs.stdenv.hostPlatform.system};
  wheel = lib.findFirst (w: lib.hasInfix wheelTag w.url) null maturinSpec.wheels;
  # Use the same hash-pinned maturin release as source installations, including
  # when nixpkgs packages an older version. These binaries run without Nix fixups.
  maturin = pkgs.runCommand "maturin-${maturinSpec.version}" { nativeBuildInputs = [ pkgs.unzip ]; } ''
    unzip ${pkgs.fetchurl { inherit (wheel) url hash; }} -d unpack
    mkdir -p "$out/bin"
    cp unpack/maturin-${maturinSpec.version}.data/scripts/maturin "$out/bin/"
    chmod +x "$out/bin/maturin"
    "$out/bin/maturin" --version
  '';
in
assert pin.tag == releaseManifest.tag;
assert sdkManifest.project.version == releaseManifest.version;
assert nativeManifest.package.version == releaseManifest.version;
assert sdkManifest.build-system.requires == [ "maturin==${maturinSpec.version}" ];
rustPlatform.buildRustPackage {
  pname = "syq-python-dist";
  version = sdkManifest.project.version;
  src = source;
  cargoLock.lockFile = "${nativeSource}/Cargo.lock";
  nativeBuildInputs = [ maturin pkgs.python313 pkgs.cargo-cyclonedx ];
  allowSubstitutes = false;
  doCheck = false;
  buildPhase = ''
    runHook preBuild
    # Nix's Python setup hook overrides this with a Nix-local platform tag.
    unset _PYTHON_HOST_PLATFORM
    export SOURCE_DATE_EPOCH=${toString epoch}
    cd sdk/python
    maturin sdist --out "$TMPDIR/dist"
    maturin pep517 write-dist-info --metadata-directory "$TMPDIR/metadata" --offline
    cd ../..
    cargo cyclonedx --format json --spec-version 1.5 \
      --target ${pkgs.stdenv.hostPlatform.rust.rustcTarget} --override-filename syq
    gzip -d -c ${nativeArchive} > "$TMPDIR/syq"
    python ${root + /scripts/package-python-wheel.py} \
      --project sdk/python --metadata "$TMPDIR/metadata" \
      --binary "$TMPDIR/syq" --platform ${platform} --sbom syq.json \
      --epoch "$SOURCE_DATE_EPOCH" --out "$TMPDIR/dist"
    cd sdk/python
    python ${root + /scripts/normalize-python-sdist.py} --epoch "$SOURCE_DATE_EPOCH" "$TMPDIR"/dist/*.tar.gz
    python ${root + /scripts/normalize-python-wheel.py} "$TMPDIR"/dist/*.whl
    cd ../..
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out"
    cp "$TMPDIR"/dist/* "$out/"
  '';
  # Preserve the exact published binary, including its existing Darwin signature.
  dontFixup = true;
}
