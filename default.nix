let
  pinned = import ./nixpkgs.nix;
  compiler = "ghc843";

in

  { pkgs ? import pinned {}
  , compiler ? "ghc843"
  }:

  pkgs.haskell.packages.${compiler}.callPackage ./yesod-auth-simple.nix { }
