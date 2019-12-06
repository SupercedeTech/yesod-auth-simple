let
  compiler = "ghc865";
  config = import ./pkgconfig.nix { inherit compiler; };
  pkgs = import ./nixpkgs.nix { inherit config; };
  hpkgs = pkgs.haskell.packages.${compiler};
  pkg = hpkgs.callPackage (import ./yesod-auth-simple.nix) {};

in
  pkg.env.overrideAttrs (oldAttrs: {
    buildInputs = oldAttrs.buildInputs ++ [
      hpkgs.hlint
      hpkgs.apply-refact
    ];
  })
