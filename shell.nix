let
  compiler = "ghc843";
  pkgs = import (import ./nixpkgs.nix) {};
  hpkgs = pkgs.haskell.packages.${compiler};
  pkg = hpkgs.callPackage (import ./yesod-auth-simple.nix) {};

in
  {}: pkg.env
