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
          version = "0.1.2";

          src = ./.;

          # Bumped by `task release VERSION=vX.Y.Z` — see
          # spec/adr/014-flake-version-sync.md and scripts/release.sh.
          # To re-pin manually: set to lib.fakeHash, run `nix build`,
          # copy the suggested hash back here.
          vendorHash = "sha256-yiQ3xI0yKcuGoZnIzs2q4ZbnKUFr4I9RJjiRtGfBAjo=";

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
