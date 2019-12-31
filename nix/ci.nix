{ pkgs ? import ./nixpkgs.nix { inherit config; }
, compiler ? "ghc865"
, config ? import ./pkgconfig.nix { inherit compiler; }
, ... }:
rec {
  yesod-auth-simple = import ../default.nix {};

  test = pkgs.nixosTest rec {
    name = "yesod-auth-simple-test";

    nodes.server = { config, pkgs, ... }: {};

    testScript = ''
      startAll;
      $server->succeed('YESOD_ENV=CI ${yesod-auth-simple}/bin/${name}');
    '';
  };
}
