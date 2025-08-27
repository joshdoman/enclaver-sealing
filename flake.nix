{
  description = "An AWS Nitro enclave with sealing using KMS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    enclaver = {
      url = "github:joshdoman/enclaver";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, enclaver }:
    let
      perSystem = (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };

          # Function to create packages for a specific target architecture
          makePackagesForTarget = targetArch:
            let
              arch = if targetArch == "aarch64" then "aarch64" else "x86_64";

              muslTarget = if targetArch == "aarch64"
                then "aarch64-unknown-linux-musl"
                else "x86_64-unknown-linux-musl";

              pkgsMusl = import nixpkgs {
                inherit system overlays;
                crossSystem = {
                  config = muslTarget;
                };
              };

              # Build the enclave server application
              sealed-enclave = pkgsMusl.rustPlatform.buildRustPackage {
                pname = "sealed-enclave";
                version = "0.1.0";
                src = ./.;

                cargoLock.lockFile = ./Cargo.lock;
                doCheck = false;

                # Statically link against musl for a minimal environment
                RUSTFLAGS = "-C target-feature=+crt-static";

                # Environment variables from Dockerfile
                RUST_LOG = "info";
                RUST_BACKTRACE = "1";

                # Create the entrypoint binary expected by enclaver
                postInstall = ''
                  ln -s $out/bin/sealed-enclave $out/bin/entrypoint
                '';
              };

              # Use enclaver's makeAppEif function
              makeAppEif = enclaver.lib.${system}.${arch}.makeAppEif or enclaver.lib.${system}.makeAppEif;

              # Build the EIF using the enclaver.yaml from root directory
              eifBuild = makeAppEif {
                appPackage = sealed-enclave;
                configFile = ./enclaver.yaml;
              };

            in {
              inherit makeAppEif;
              eif = eifBuild.eif;
              rootfs = eifBuild.rootfs;
              app = sealed-enclave;
            };

          # Native architecture
          nativeArch = if pkgs.stdenv.isAarch64 then "aarch64" else "x86_64";
          nativePackages = makePackagesForTarget nativeArch;

          # Cross-compilation targets
          x86Packages = makePackagesForTarget "x86_64";
          aarch64Packages = makePackagesForTarget "aarch64";

        in
        {
          lib = {
            # Native architecture
            makeAppEif = nativePackages.makeAppEif;
            
            # Architecture-specific builders
            x86_64.makeAppEif = x86Packages.makeAppEif;
            aarch64.makeAppEif = aarch64Packages.makeAppEif;
          };

          packages = {
            # Default to native EIF for enclave builds
            default = nativePackages.eif;
            
            # Native packages
            app = nativePackages.app;
            rootfs = nativePackages.rootfs;
            eif = nativePackages.eif;

            # Cross-compilation targets
            x86_64-eif = x86Packages.eif;
            aarch64-eif = aarch64Packages.eif;
            x86_64-app = x86Packages.app;
            aarch64-app = aarch64Packages.app;

            # Convenience aliases
            intel-eif = x86Packages.eif;
            graviton-eif = aarch64Packages.eif;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              pkg-config
              openssl
              ca-certificates
              curl
              dnsutils
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];

            # Development environment variables
            RUST_LOG = "debug";
            RUST_BACKTRACE = "1";
            LOCAL = "true";
          };

          # Development apps for easy testing
          apps = {
            default = flake-utils.lib.mkApp {
              drv = nativePackages.app;
              name = "sealed-enclave";
            };
          };
        });
    in
      flake-utils.lib.eachDefaultSystem perSystem;
}