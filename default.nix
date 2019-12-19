{ pkgs ? import ./nix/nixpkgs.nix { inherit config; }
, config ? import ./nix/pkgconfig.nix { inherit compiler; }
, compiler ? "ghc865"
}:

let
  inherit (import ./nix/gitignoreSource.nix { inherit (pkgs) lib; }) gitignoreSource;
in
  pkgs.haskell.lib.overrideCabal (pkgs.haskell.packages.${compiler}.callPackage ./yesod-auth-simple.nix {}) (drv: {
    src = gitignoreSource ./.;
    configureFlags = ["-f-library-only"];
    doCheck = false;
    testHaskellDepends = [];
    testToolDepends = [];
    doHaddock = false;
    enableLibraryProfiling = false;
    enableSeparateDataOutput = false;
    enableSharedExecutables = false;
    isLibrary = false;
    postFixup = "rm -rf $out/lib $out/nix-support $out/share/doc";
  })
