{ pkgs ? import ./nix/nixpkgs.nix { inherit config; }
, config ? import ./nix/pkgconfig.nix { inherit compiler; }
, compiler ? "ghc865"
}:

let
  inherit (import ./nix/gitignoreSource.nix { inherit (pkgs) lib; }) gitignoreSource;
in
pkgs.haskell.packages.${compiler}.callCabal2nix "yesod-auth-simple" (gitignoreSource ./.) {}
