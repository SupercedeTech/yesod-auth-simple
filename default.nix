let
  pinned = import ./nixpkgs.nix;
  compiler = "ghc865";

in

  { pkgs ? import pinned { inherit config; }
  , config ? import ./pkgconfig.nix { inherit compiler; }
  , compiler ? "ghc865"
  }:

  pkgs.haskell.packages.${compiler}.callPackage ./yesod-auth-simple.nix { }
