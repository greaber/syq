{
  description = "Reproducible syq release binaries and Python distributions";

  inputs = {
    crane.url = "github:ipetkov/crane/v0.24.0";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          lib = pkgs.lib;
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          # Nix removes these SDK stubs in favor of its own libiconv dylib.
          # Standalone executables must instead reference macOS's system copy.
          systemLibiconv = pkgs.runCommand "syq-system-libiconv" { } ''
            mkdir -p "$out/lib"
            cp -d ${pkgs.apple-sdk.src}/usr/lib/libiconv*.tbd "$out/lib/"
          '';
          # Keep Cargo's flags stable across Nix sandbox directories. Apply
          # path normalization inside wrappers so cached dependencies stay fresh.
          rustcWrapper = pkgs.writeShellScript "syq-release-rustc" ''
            exec "$@" --remap-path-prefix="$NIX_BUILD_TOP"=/build \
              ${lib.optionalString pkgs.stdenv.isDarwin ''-C link-arg=-Wl,-oso_prefix,"$NIX_BUILD_TOP/"''}
          '';
          cWrapper = compiler: pkgs.writeShellScript "syq-release-${compiler}" ''
            exec ${pkgs.stdenv.cc}/bin/${compiler} \
              -ffile-prefix-map="$NIX_BUILD_TOP"=/build "$@"
          '';
          releaseArgs = {
            pname = "syq";
            version = manifest.package.version;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./build.rs ./src ];
            };
            cargoExtraArgs = "--locked --bin syq";
            # The ordinary test suites run separately; this derivation produces
            # the distributable executable and checks its release identity.
            doCheck = false;
            env = {
              CARGO_BUILD_TARGET = pkgs.stdenv.hostPlatform.rust.rustcTarget;
              RUSTC_WRAPPER = rustcWrapper;
              CC = cWrapper "cc";
              CXX = cWrapper "c++";
              RUSTFLAGS = if pkgs.stdenv.isLinux
                then "-C target-feature=+crt-static -L native=${pkgs.glibc.static}/lib"
                else "-L native=${systemLibiconv}/lib";

            };
            # Keep the deployment targets of the published v0.6.0 binaries.
            # Build tools may require a newer macOS than the produced executable.
            preBuild = lib.optionalString pkgs.stdenv.isDarwin ''
              export MACOSX_DEPLOYMENT_TARGET=${if system == "x86_64-darwin" then "10.12" else "11.0"}
            '';
          };
          # A syq version bump does not change third-party dependencies. Keep
          # the placeholder crate and its lock entry version-neutral as well.
          depsLib = craneLib.overrideScope (_final: prev: {
            cleanCargoToml = args:
              let cleaned = prev.cleanCargoToml args;
              in cleaned // { package = cleaned.package // { version = "0.0.0"; }; };
          });
          release-deps = depsLib.buildDepsOnly (releaseArgs // {
            version = "0.0.0";
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [ ./Cargo.toml ./build.rs ./src ];
            };
            cargoLock = builtins.toFile "Cargo.lock" (builtins.replaceStrings
              [ ''name = "syq"
version = "${manifest.package.version}"'' ]
              [ ''name = "syq"
version = "0.0.0"'' ]
              (builtins.readFile ./Cargo.lock));
            cargoVendorDir = craneLib.vendorCargoDeps { src = releaseArgs.src; };
            # Only release dependencies are needed, not cargo-check metadata.
            buildPhaseCargoCommand = "cargo build --release --locked --bin syq";
          });
          release = craneLib.buildPackage (releaseArgs // {
            cargoArtifacts = release-deps;
            allowSubstitutes = false;
            env = releaseArgs.env // {
              SYQ_RELEASE_BUILD = "1";
              SYQ_RELEASE_PUBLIC_KEY = lib.strings.trim (builtins.readFile ./src/release-public-key.txt);
            };
            # Nix strips the standalone binary with its pinned tools.
            # Compress only after final stripping and Darwin signing fixups.
            dontPatchELF = true;
            postFixup = ''
              test "$("$out/bin/syq" --version)" = "syq ${manifest.package.version}"
              test "$("$out/bin/syq" --build-identity)" = "v${manifest.package.version}"
              ${pkgs.gzip}/bin/gzip -9 -n -c "$out/bin/syq" > "$out/bin/syq.gz"
            '';
          });
        in {
          inherit release release-deps;
          default = release;
          python-dist = import ./nix/python-dist.nix {
            inherit pkgs;
            root = ./.;
            epoch = self.lastModified;
          };
        });
    };
}
