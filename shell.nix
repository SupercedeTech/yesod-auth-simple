let
  compiler = "ghc902";
  config = import ./nix/pkgconfig.nix { inherit compiler; };
  pkgs = import ./nix/nixpkgs.nix { inherit config; };
  hpkgs = pkgs.haskell.packages.${compiler};
  pkg = import ./default.nix {inherit compiler; inherit pkgs; inherit config;};

in
  pkg.env.overrideAttrs (oldAttrs: {
    buildInputs = oldAttrs.buildInputs ++ [
      hpkgs.hlint
      hpkgs.cabal-install
      hpkgs.apply-refact
    ];
  })
