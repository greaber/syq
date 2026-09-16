{
  description = "Reproducible standalone syq release binaries";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          lib = pkgs.lib;
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
          manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          release = rustPlatform.buildRustPackage {
            pname = "syq";
            version = manifest.package.version;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./build.rs ./src ];
            };
            allowSubstitutes = false;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--bin" "syq" ];
            # The ordinary test suites run separately; this derivation produces
            # the distributable executable and checks its release identity.
            doCheck = false;
            env = {
              SYQ_RELEASE_BUILD = "1";
              SYQ_RELEASE_PUBLIC_KEY = lib.strings.trim (builtins.readFile ./src/release-public-key.txt);
              RUSTFLAGS = lib.optionalString pkgs.stdenv.isLinux "-C target-feature=+crt-static -L native=${pkgs.glibc.static}/lib";
            };
            # Keep the deployment targets of the published v0.6.0 binaries.
            # Build tools may require a newer macOS than the produced executable.
            preBuild = lib.optionalString pkgs.stdenv.isDarwin ''
              export MACOSX_DEPLOYMENT_TARGET=${if system == "x86_64-darwin" then "10.12" else "11.0"}
            '';
            # buildRustPackage delegates stripping to Nix's pinned tools.
            # Compress only after final stripping and Darwin signing fixups.
            dontPatchELF = true;
            postFixup = ''
              test "$("$out/bin/syq" --version)" = "syq ${manifest.package.version}"
              test "$("$out/bin/syq" --build-identity)" = "v${manifest.package.version}"
              ${pkgs.gzip}/bin/gzip -9 -n -c "$out/bin/syq" > "$out/bin/syq.gz"
            '';
          };
        in { inherit release; default = release; });
    };
}
