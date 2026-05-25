{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      forEachSystem = nixpkgs.lib.genAttrs [
        "x86_64-darwin"
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];

      # Single source of truth for the package definition; reused by
      # packages.default, apps.default, and checks.default.
      mkPackage = pkgs:
        pkgs.buildGoModule rec {
          pname = "nebula-pki";
          version = "0.0.1";

          src = ./.;

          # Bump when go.mod changes. Set to lib.fakeHash, run `nix build`,
          # copy the suggested hash back here.
          vendorHash = "sha256-c8ncCvckHEGT5qlzMzQubiuP5Ars0z9zNMQmV8q3mp4=";

          subPackages = [ "cmd/nebula-pki" ];

          ldflags = [
            "-s" "-w"
            "-X github.com/anverse/nebula-pki/internal/buildinfo.Version=${version}"
            "-X github.com/anverse/nebula-pki/internal/buildinfo.Commit=nix"
            "-X github.com/anverse/nebula-pki/internal/buildinfo.Date=1970-01-01T00:00:00Z"
          ];

          meta = with pkgs.lib; {
            description = "Declarative wrapper around nebula-cert";
            homepage = "https://github.com/anverse/nebula-pki";
            license = licenses.mit;
            mainProgram = "nebula-pki";
          };
        };
    in
    {
      devShells = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              go-task
              goreleaser
            ];

            shellHook = ''
              echo "tools"
              echo "  go         $(go version)"
              echo "  task       $(task --version)"
              echo "  goreleaser $(goreleaser --version 2>&1 | awk -F'[: ]+' '/^GitVersion:/{print $2; exit}')"
            '';
          };
        }
      );

      packages = forEachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = mkPackage pkgs;
          nebula-pki = mkPackage pkgs;
        }
      );

      apps = forEachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nebula-pki";
        };
      });

      checks = forEachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = mkPackage pkgs;
        }
      );
    };
}
