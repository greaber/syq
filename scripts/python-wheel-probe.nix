{ attempt ? "first" }:
let
  root = ../.;
  flake = builtins.getFlake (toString root);
  pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; };
  source = ../target/python-repro/source;
  lock = builtins.fromTOML (builtins.readFile (root + /sdk/python/uv.lock));
  maturinSpec = builtins.head (builtins.filter (p: p.name == "maturin") lock.package);
  wheel = builtins.head (builtins.filter (w: pkgs.lib.hasInfix "macosx_10_12_universal2" w.url) maturinSpec.wheels);
  maturin = pkgs.runCommand "maturin-1.15.0" { nativeBuildInputs = [ pkgs.unzip ]; } ''
    unzip ${pkgs.fetchurl { inherit (wheel) url; hash = wheel.hash; }} -d unpack
    mkdir -p $out/bin
    cp unpack/maturin-1.15.0.data/scripts/maturin $out/bin/
    chmod +x $out/bin/maturin
    $out/bin/maturin --version
  '';
in flake.packages.${builtins.currentSystem}.release.overrideAttrs (old: {
  pname = "syq-python-probe-${attempt}";
  src = source;
  cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = source + /Cargo.lock; };
  nativeBuildInputs = old.nativeBuildInputs ++ [ maturin pkgs.python313 ];
  buildPhase = ''
    runHook preBuild
    unset _PYTHON_HOST_PLATFORM
    export SOURCE_DATE_EPOCH=1789697110
    cd sdk/python
    maturin sdist --out "$TMPDIR/dist"
    maturin build --release --strip --compatibility pypi --target aarch64-apple-darwin --offline --out "$TMPDIR/dist"
    ${pkgs.python313}/bin/python ${root + /scripts/normalize-python-sdist.py} --epoch "$SOURCE_DATE_EPOCH" "$TMPDIR"/dist/*.tar.gz
    cd ../..
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out"
    cp "$TMPDIR"/dist/* "$out/"
  '';
  postFixup = "";
  dontFixup = true;
})
