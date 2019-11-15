let
  compiler = "ghc865";
  pkgs = import ./nixpkgs.nix {};
  hpkgs = pkgs.haskell.packages.${compiler};
  pkg = hpkgs.callPackage (import ./yesod-auth-simple.nix) {};

in
  {}: pkg.env
