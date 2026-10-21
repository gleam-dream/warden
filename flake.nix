{
  description = "Development environment for warden";

  inputs = {
    design-layer.url = "github:lostbean/design-layer/main";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      design-layer,
      nixpkgs,
      flake-utils,
      treefmt-nix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          settings.global.excludes = [
            "**/*.pdf"
            ".render/**"
            "docs/evidence/**" # Frozen regression receipts retain their original bytes.
            "test/integration/oidcc_records.hrl" # Pinned oracle record declarations.
            "test_negative/**" # Deliberately invalid compiler fixtures.
          ];
          programs.gleam.enable = true;
          programs.nixfmt.enable = true;
          programs.prettier.enable = true;
        };
      in
      {
        apps.snips = design-layer.apps.${system}.snips;
        apps.design-gate-check = design-layer.apps.${system}.check;
        apps.design-gate-render = design-layer.apps.${system}.render;
        apps.design-gate-context = design-layer.apps.${system}.context;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            lefthook
            gleam
            beam29Packages.erlang
            beam29Packages.rebar3
            postgresql_16
            openssl
            nodejs_22
            python3
            curl
            lsof
            git
          ];
        };

        formatter = treefmtEval.config.build.wrapper;

        checks.formatting = treefmtEval.config.build.check ./.;
      }
    );
}
